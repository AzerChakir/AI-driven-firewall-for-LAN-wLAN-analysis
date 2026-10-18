"""Packet acquisition: live sniffing (scapy) and offline pcap replay.

Only IPv4 TCP/UDP packets are decoded; everything else is ignored, matching
the flow meter's scope.

scapy is imported lazily (and in full, as ``scapy.all``) so that every link
layer type - Ethernet, SLL, raw IP - is registered before a capture file is
read.
"""

from __future__ import annotations

import logging
import queue
from pathlib import Path
from typing import Callable, Optional

from .flowmeter import PROTO_TCP, PROTO_UDP, PacketRec

log = logging.getLogger("idsfw.capture")

_SCAPY = None


def scapy_all():
    """Imports (once) and returns the ``scapy.all`` module."""
    global _SCAPY
    if _SCAPY is None:
        import scapy.all as scapy_all_module  # noqa: PLC0415 - lazy import

        _SCAPY = scapy_all_module
    return _SCAPY


def decode_packet(pkt, ts: float | None = None) -> Optional[PacketRec]:
    """Converts a scapy packet into a :class:`PacketRec` (or None if not IPv4 TCP/UDP)."""
    scapy = scapy_all()
    ip = pkt.getlayer(scapy.IP)
    if ip is None:
        return None

    if pkt.haslayer(scapy.TCP):
        tcp = pkt[scapy.TCP]
        proto = PROTO_TCP
        payload_len = len(bytes(tcp.payload))
        window = int(tcp.window)
        flags = int(tcp.flags)
        sport, dport = int(tcp.sport), int(tcp.dport)
    elif pkt.haslayer(scapy.UDP):
        udp = pkt[scapy.UDP]
        proto = PROTO_UDP
        payload_len = len(bytes(udp.payload))
        window = 0
        flags = 0
        sport, dport = int(udp.sport), int(udp.dport)
    else:
        return None

    timestamp = float(pkt.time if ts is None else ts)
    wire_len = int(getattr(pkt, "wirelen", 0) or len(pkt))
    return PacketRec(
        ts_us=int(round(timestamp * 1_000_000)),
        proto=proto,
        src_ip=ip.src,
        dst_ip=ip.dst,
        src_port=sport,
        dst_port=dport,
        payload_len=payload_len,
        wire_len=wire_len,
        tcp_window=window,
        flags=flags,
    )


def make_queue_callback(
    work_queue: "queue.Queue[PacketRec]",
    on_drop: Callable[[int], None] | None = None,
    on_error: Callable[[], None] | None = None,
) -> Callable[[object], None]:
    """Builds a scapy ``prn`` callback that pushes decoded packets to a queue."""

    def callback(pkt) -> None:
        try:
            record = decode_packet(pkt)
        except Exception:  # malformed packet - never kill the sniffer
            if on_error:
                on_error()
            return
        if record is None:
            return
        try:
            work_queue.put_nowait(record)
        except queue.Full:
            if on_drop:
                on_drop(1)

    return callback


class LiveCapture:
    """Wraps scapy's AsyncSniffer so it can be started/stopped deterministically."""

    def __init__(
        self,
        interface: str,
        bpf_filter: str = "ip and (tcp or udp)",
        snaplen: int = 256,
        promiscuous: bool = True,
        callback: Callable[[object], None] | None = None,
    ) -> None:
        self.interface = interface
        self.bpf_filter = bpf_filter
        self.snaplen = snaplen
        self.promiscuous = promiscuous
        self.callback = callback
        self._sniffer = None

    def start(self) -> None:
        log.info(
            "starting live capture on %s (filter=%r, snaplen=%s, promisc=%s)",
            self.interface,
            self.bpf_filter,
            self.snaplen,
            self.promiscuous,
        )
        self._sniffer = scapy_all().AsyncSniffer(
            iface=self.interface,
            filter=self.bpf_filter or None,
            prn=self.callback,
            store=False,
            promisc=self.promiscuous,
            snaplen=self.snaplen,
        )
        self._sniffer.start()

    def stop(self) -> None:
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as exc:  # pragma: no cover
                log.debug("sniffer stop failed: %s", exc)
            self._sniffer = None


def replay_pcap(
    path: str | Path,
    callback: Callable[[object], None],
    limit: int | None = None,
) -> int:
    """Feeds a capture file through ``callback`` (used for offline validation)."""
    scapy = scapy_all()
    count = 0
    path = Path(path)
    log.info("replaying %s", path)
    with scapy.PcapReader(str(path)) as reader:
        for pkt in reader:
            callback(pkt)
            count += 1
            if limit and count >= limit:
                break
    log.info("replayed %s packets from %s", count, path)
    return count
