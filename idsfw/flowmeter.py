"""CICFlowMeter V4 (Java) compatible bidirectional flow meter.

The trained model was fed with features produced by the official Java
CICFlowMeter (``ahlashkari/CICFlowMeter``, the tool behind the CICIDS2017 /
CSE-CIC-IDS2018 datasets).  To avoid train/deploy skew, this module reproduces
its semantics *including its quirks*:

* packet length = **transport payload length** (TCP/UDP payload), not frame size;
* the first packet's payload is added **twice** to the global packet-length
  statistics (``flowLengthStats``) in the original ``BasicFlow.firstPacket``;
* ``Down/Up Ratio`` performs **integer** division ``bwd_pkts / fwd_pkts``;
* standard deviations use the **bias-corrected sample** formula (n - 1),
  as in Apache Commons Math ``SummaryStatistics.getVariance()``;
* ``NAN`` is emitted when a statistic has no observations (single-packet flows);
* flow lifetime is 120 s (``flowTimeOut``) and an idle gap is any inter-packet
  gap larger than 5 s (``activityTimeout``);
* a flow is terminated by a backward FIN (Java bug: ``bwdFIN + bwdFIN == 2``),
  by a RST, by the 120 s lifetime, or - our addition for live capture - by
  an idle timeout.

Only IPv4 TCP/UDP packets are tracked (the model was trained on IPv4).

``FlowMeter`` is deliberately free of any scapy dependency: it consumes
:class:`PacketRec` objects, which makes the feature math unit-testable without
root privileges or a network interface.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Optional

# --- CICFlowMeter constants (Cmd.java / CICFlowMeter.java) -------------------
FLOW_TIMEOUT_US = 120_000_000  # new flow after 120 s of flow lifetime
ACTIVITY_TIMEOUT_US = 5_000_000  # idle gap threshold (5 s)
SUBFLOW_GAP_US = 1_000_000  # 1 s: threshold used by detectUpdateSubflows()

PROTO_TCP = 6
PROTO_UDP = 17

# TCP flag bits (scapy layout)
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

NAN = float("nan")


@dataclass(slots=True)
class PacketRec:
    """One IPv4 TCP/UDP packet, already decoded from the wire."""

    ts_us: int
    proto: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    payload_len: int
    wire_len: int = 0
    tcp_window: int = 0
    flags: int = 0

    @property
    def is_tcp(self) -> bool:
        return self.proto == PROTO_TCP


class SumStats:
    """Streaming summary statistics mimicking commons-math ``SummaryStatistics``.

    ``mean``/``std`` are NaN with no observations, ``std`` is 0.0 with a single
    observation and the bias-corrected (n - 1) value otherwise.
    """

    __slots__ = ("n", "_sum", "_mean", "_m2", "min", "max")

    def __init__(self) -> None:
        self.n = 0
        self._sum = 0.0
        self._mean = 0.0
        self._m2 = 0.0
        self.min = NAN
        self.max = NAN

    def add(self, value: float) -> None:
        value = float(value)
        self.n += 1
        self._sum += value
        delta = value - self._mean
        self._mean += delta / self.n
        self._m2 += delta * (value - self._mean)
        if self.n == 1:
            self.min = self.max = value
        else:
            if value < self.min:
                self.min = value
            if value > self.max:
                self.max = value

    @property
    def mean(self) -> float:
        return NAN if self.n == 0 else self._mean

    def variance(self) -> float:
        if self.n == 0:
            return NAN
        if self.n == 1:
            return 0.0
        return self._m2 / (self.n - 1)

    def std(self) -> float:
        var = self.variance()
        return NAN if math.isnan(var) else math.sqrt(var)

    def get_sum(self) -> float:
        return NAN if self.n == 0 else self._sum


def _iat_stats(timestamps: list[int]) -> SumStats:
    stats = SumStats()
    for prev, cur in zip(timestamps, timestamps[1:]):
        stats.add(cur - prev)
    return stats


class Flow:
    """State of one bidirectional flow, mirroring ``BasicFlow``."""

    __slots__ = (
        "src_ip", "src_port", "dst_ip", "dst_port", "proto",
        "start_ts", "last_ts", "end_active_ts", "last_eval_ts",
        "init_fwd_win",
        "flow_len", "fwd_len", "bwd_len",
        "fwd_n", "bwd_n",
        "fwd_ts", "bwd_ts", "flow_iat",
        "idle",
        "flags_total", "fwd_fin", "bwd_fin",
    )

    def __init__(self, pkt: PacketRec, anchor: Optional[tuple[str, int]] = None) -> None:
        # ``anchor`` reproduces the Java "restart flow after 120 s" constructor:
        # the first packet is always processed as forward, then the flow keeps
        # the previous flow's source orientation.
        self.flow_len = SumStats()
        self.fwd_len = SumStats()
        self.bwd_len = SumStats()
        self.flow_iat = SumStats()
        self.idle = SumStats()
        self.fwd_ts: list[int] = []
        self.bwd_ts: list[int] = []
        self.flags_total = {FIN: 0, SYN: 0, RST: 0, PSH: 0, ACK: 0, URG: 0, ECE: 0, CWR: 0}
        self.fwd_fin = 0
        self.bwd_fin = 0
        self.fwd_n = 0
        self.bwd_n = 0
        self.init_fwd_win = 0

        # firstPacket(): the generic add happens before the direction branch,
        # so the first payload lands twice in flowLengthStats (Java quirk).
        self.flow_len.add(pkt.payload_len)

        self.src_ip = pkt.src_ip
        self.src_port = pkt.src_port
        self.dst_ip = pkt.dst_ip
        self.dst_port = pkt.dst_port
        self.proto = pkt.proto
        self.start_ts = pkt.ts_us
        self.last_ts = pkt.ts_us
        self.end_active_ts = pkt.ts_us
        self.last_eval_ts = pkt.ts_us

        self._check_flags(pkt)
        self._add_forward_first(pkt)

        if anchor is not None:
            self.src_ip, self.src_port = anchor

    # -- direction helpers ---------------------------------------------------
    def is_forward(self, pkt: PacketRec) -> bool:
        return pkt.src_ip == self.src_ip and pkt.src_port == self.src_port

    def flow_key(self) -> tuple:
        return (self.proto, self.src_ip, self.src_port, self.dst_ip, self.dst_port)

    # -- ingestion -----------------------------------------------------------
    def _check_flags(self, pkt: PacketRec) -> None:
        for bit in self.flags_total:
            if pkt.flags & bit:
                self.flags_total[bit] += 1

    def _add_forward_first(self, pkt: PacketRec) -> None:
        self.flow_len.add(pkt.payload_len)  # second add for the first packet
        self.fwd_len.add(pkt.payload_len)
        self.fwd_n += 1
        self.fwd_ts.append(pkt.ts_us)
        self.init_fwd_win = pkt.tcp_window

    def update_active_idle(self, ts_us: int) -> None:
        """``BasicFlow.updateActiveIdleTime`` (active part omitted, unused)."""
        if ts_us - self.end_active_ts > ACTIVITY_TIMEOUT_US:
            self.idle.add(ts_us - self.end_active_ts)
        self.end_active_ts = ts_us

    def add_packet(self, pkt: PacketRec, *, idle_prechecked: bool = False) -> None:
        """``BasicFlow.addPacket``. ``idle_prechecked`` is True when the caller
        already ran ``update_active_idle`` for this packet (normal path) - in
        that case we still need the ``detectUpdateSubflows`` gap test, which is
        a no-op because end_active_ts was just set, but for terminating packets
        the caller skips the pre-check so the subflow rule is applied here."""
        if not idle_prechecked:
            prev_ts = self.last_ts
            if pkt.ts_us - prev_ts > SUBFLOW_GAP_US:
                self.update_active_idle(pkt.ts_us)

        self._check_flags(pkt)

        if self.is_forward(pkt):
            self.flow_len.add(pkt.payload_len)
            self.fwd_len.add(pkt.payload_len)
            self.fwd_n += 1
            self.flow_iat.add(pkt.ts_us - self.last_ts)
            self.fwd_ts.append(pkt.ts_us)
        else:
            self.flow_len.add(pkt.payload_len)
            self.bwd_len.add(pkt.payload_len)
            self.bwd_n += 1
            self.flow_iat.add(pkt.ts_us - self.last_ts)
            self.bwd_ts.append(pkt.ts_us)

        self.last_ts = pkt.ts_us

    # -- feature extraction --------------------------------------------------
    def packet_count(self) -> int:
        return self.fwd_n + self.bwd_n

    def duration_us(self) -> int:
        return self.last_ts - self.start_ts

    def down_up_ratio(self) -> float:
        if self.fwd_n > 0:
            return float(self.bwd_n // self.fwd_n)  # Java integer division
        return 0.0

    def features(self) -> dict:
        """Feature dict using the original CICFlowMeter CSV column names."""
        fwd_iat = _iat_stats(self.fwd_ts)
        bwd_iat = _iat_stats(self.bwd_ts)
        dur = self.duration_us()
        pkt_count = self.packet_count()

        data: dict[str, float | int | str] = {
            # --- identity / metadata (not model inputs) ---
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "Protocol": self.proto,
            "timestamp_us": self.start_ts,
            "last_seen_us": self.last_ts,
            # --- CICFlowMeter columns ---
            "Destination Port": self.dst_port,
            "Flow Duration": dur,
            "Total Fwd Packets": self.fwd_n,
            "Total Backward Packets": self.bwd_n,
            "Total Length of Fwd Packets": self.fwd_len.get_sum(),
            "Total Length of Bwd Packets": self.bwd_len.get_sum(),
            "Fwd Packet Length Max": self.fwd_len.max if self.fwd_n else 0,
            "Fwd Packet Length Min": self.fwd_len.min if self.fwd_n else 0,
            "Fwd Packet Length Mean": self.fwd_len.mean if self.fwd_n else 0,
            "Fwd Packet Length Std": self.fwd_len.std() if self.fwd_n else 0,
            "Bwd Packet Length Max": self.bwd_len.max if self.bwd_n else 0,
            "Bwd Packet Length Min": self.bwd_len.min if self.bwd_n else 0,
            "Bwd Packet Length Mean": self.bwd_len.mean if self.bwd_n else 0,
            "Bwd Packet Length Std": self.bwd_len.std() if self.bwd_n else 0,
            # flow IAT: unguarded in the Java dumper -> NaN for single-packet flows
            "Flow IAT Mean": self.flow_iat.mean,
            "Flow IAT Std": self.flow_iat.std(),
            "Flow IAT Max": self.flow_iat.max,
            "Flow IAT Min": self.flow_iat.min,
            "Fwd IAT Total": fwd_iat.get_sum() if self.fwd_n > 1 else 0,
            "Fwd IAT Mean": fwd_iat.mean if self.fwd_n > 1 else 0,
            "Fwd IAT Std": fwd_iat.std() if self.fwd_n > 1 else 0,
            "Fwd IAT Max": fwd_iat.max if self.fwd_n > 1 else 0,
            "Fwd IAT Min": fwd_iat.min if self.fwd_n > 1 else 0,
            "Bwd IAT Total": bwd_iat.get_sum() if self.bwd_n > 1 else 0,
            "Bwd IAT Mean": bwd_iat.mean if self.bwd_n > 1 else 0,
            "Bwd IAT Std": bwd_iat.std() if self.bwd_n > 1 else 0,
            "Bwd IAT Max": bwd_iat.max if self.bwd_n > 1 else 0,
            "Bwd IAT Min": bwd_iat.min if self.bwd_n > 1 else 0,
            "FIN Flag Count": self.flags_total[FIN],
            "SYN Flag Count": self.flags_total[SYN],
            "RST Flag Count": self.flags_total[RST],
            "PSH Flag Count": self.flags_total[PSH],
            "ACK Flag Count": self.flags_total[ACK],
            "URG Flag Count": self.flags_total[URG],
            "CWR Flag Count": self.flags_total[CWR],
            "ECE Flag Count": self.flags_total[ECE],
            "Down/Up Ratio": self.down_up_ratio(),
            "Avg Packet Size": (self.flow_len.get_sum() / pkt_count) if pkt_count else 0,
            "Avg Fwd Segment Size": self.fwd_len.mean if self.fwd_n else 0,
            "Avg Bwd Segment Size": self.bwd_len.mean if self.bwd_n else 0,
            "Packet Length Min": self.flow_len.min if pkt_count else 0,
            "Packet Length Max": self.flow_len.max if pkt_count else 0,
            "Packet Length Mean": self.flow_len.mean if pkt_count else 0,
            "Packet Length Std": self.flow_len.std() if pkt_count else 0,
            "Packet Length Variance": self.flow_len.variance() if pkt_count else 0,
            "Init Fwd Win Bytes": self.init_fwd_win,
            "Init Bwd Win Bytes": 0,
            "Idle Mean": self.idle.mean if self.idle.n else 0,
            "Idle Std": self.idle.std() if self.idle.n else 0,
            "Idle Max": self.idle.max if self.idle.n else 0,
            "Idle Min": self.idle.min if self.idle.n else 0,
        }

        # --- engineered (training-pipeline) features: numpy.log1p ---
        data["FE_Log_Flow_Duration"] = math.log1p(dur)
        data["FE_Log_Total_Fwd_Packets"] = math.log1p(self.fwd_n)
        data["FE_Log_Total_Backward_Packets"] = math.log1p(self.bwd_n)
        return data


class FlowMeter:
    """Groups :class:`PacketRec` into flows and emits finished ones."""

    def __init__(
        self,
        flow_timeout_us: int = FLOW_TIMEOUT_US,
        idle_timeout_us: Optional[int] = None,
        active_timeout_us: Optional[int] = None,
        min_packets: int = 2,
    ) -> None:
        self.flow_timeout_us = flow_timeout_us
        # live-capture extra: emit flows that stopped receiving packets
        self.idle_timeout_us = flow_timeout_us if idle_timeout_us is None else idle_timeout_us
        self.active_timeout_us = active_timeout_us
        self.min_packets = min_packets
        self._flows: dict[tuple, Flow] = {}
        self.started = 0
        self.discarded_single_packet = 0

    # -- public API ----------------------------------------------------------
    def add_packet(self, pkt: PacketRec) -> list[Flow]:
        emitted: list[Flow] = []
        key = (pkt.proto, pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
        rev = (pkt.proto, pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port)
        flow = self._flows.get(key) or self._flows.get(rev)

        if flow is None:
            self._flows[key] = Flow(pkt)
            self.started += 1
            return emitted

        # 120 s flow lifetime: finish the old flow, restart with this packet
        if pkt.ts_us - flow.start_ts > self.flow_timeout_us:
            if flow.packet_count() >= self.min_packets:
                emitted.append(flow)
            else:
                self.discarded_single_packet += 1
            self._flows[flow.flow_key()] = Flow(pkt, anchor=(flow.src_ip, flow.src_port))
            self.started += 1
            return emitted

        if pkt.flags & FIN:
            finished = self._handle_fin(flow, pkt)
            if finished is None:
                return emitted
            emitted.append(finished)
            del self._flows[flow.flow_key()]
            return emitted

        if pkt.flags & RST:
            flow.add_packet(pkt)
            emitted.append(flow)
            del self._flows[flow.flow_key()]
            return emitted

        # normal packet (reproduces the Java "already closed" discard rule)
        if flow.is_forward(pkt) and flow.fwd_fin == 0:
            flow.update_active_idle(pkt.ts_us)
            flow.add_packet(pkt, idle_prechecked=True)
        elif flow.bwd_fin == 0:
            flow.update_active_idle(pkt.ts_us)
            flow.add_packet(pkt, idle_prechecked=True)
        # else: flow already closed -> discard packet

        # Periodic active-flow evaluation for real-time threat detection
        if (
            self.active_timeout_us
            and (pkt.ts_us - flow.last_eval_ts >= self.active_timeout_us)
            and flow.packet_count() >= self.min_packets
        ):
            flow.last_eval_ts = pkt.ts_us
            emitted.append(flow)

        return emitted

    def flush(self, now_us: int) -> list[Flow]:
        """Emit flows idle for longer than the idle timeout (live capture)."""
        emitted: list[Flow] = []
        for key, flow in list(self._flows.items()):
            if now_us - flow.last_ts >= self.idle_timeout_us:
                if flow.packet_count() >= self.min_packets:
                    emitted.append(flow)
                else:
                    self.discarded_single_packet += 1
                del self._flows[key]
        return emitted

    def active_flow_count(self) -> int:
        return len(self._flows)

    def flush_all(self) -> list[Flow]:
        """Force-emit every remaining flow (end of an offline replay)."""
        emitted = []
        for flow in self._flows.values():
            if flow.packet_count() >= self.min_packets:
                emitted.append(flow)
            else:
                self.discarded_single_packet += 1
        self._flows.clear()
        return emitted

    # -- internals -----------------------------------------------------------
    def _handle_fin(self, flow: Flow, pkt: PacketRec) -> Optional[Flow]:
        """Port of the (buggy) FIN handling in ``FlowGenerator.addPacket``."""
        if flow.is_forward(pkt):
            flow.fwd_fin += 1
            if flow.fwd_fin != 1:
                return None  # "some error" -> packet dropped
            if flow.bwd_fin + flow.bwd_fin == 2:  # i.e. bwd_fin == 1
                flow.add_packet(pkt)
                return flow
            flow.update_active_idle(pkt.ts_us)
            flow.add_packet(pkt, idle_prechecked=True)
            return None
        flow.bwd_fin += 1
        if flow.bwd_fin != 1:
            return None
        if flow.bwd_fin + flow.bwd_fin == 2:  # always true after first bwd FIN
            flow.add_packet(pkt)
            return flow
        return None
