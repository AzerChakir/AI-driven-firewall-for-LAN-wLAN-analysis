"""Feature-fidelity tests for the CICFlowMeter-compatible flow meter.

These tests encode the *hand-computed* expectations, so a regression in the
feature math (which would silently poison the model) fails loudly.
"""

from __future__ import annotations

import math
from pathlib import Path

import pytest

from idsfw.flowmeter import FIN, PSH, RST, SYN, ACK, PROTO_TCP, PROTO_UDP, FlowMeter, PacketRec

BASE = 1_000_000  # µs


def tcp(ts_us, *, fwd=True, payload=0, flags=0, window=0, src="10.0.0.2", dst="10.0.0.9", sport=51000, dport=443):
    if not fwd:
        src, dst, sport, dport = dst, src, dport, sport
    return PacketRec(
        ts_us=ts_us,
        proto=PROTO_TCP,
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        payload_len=payload,
        wire_len=payload + 54,
        tcp_window=window,
        flags=flags,
    )


def udp(ts_us, *, fwd=True, payload=0):
    src, dst, sport, dport = ("10.0.0.2", "8.8.8.8", 40000, 53)
    if not fwd:
        src, dst, sport, dport = dst, src, dport, sport
    return PacketRec(
        ts_us=ts_us,
        proto=PROTO_UDP,
        src_ip=src,
        dst_ip=dst,
        src_port=sport,
        dst_port=dport,
        payload_len=payload,
        wire_len=payload + 42,
    )


def collect(meter: FlowMeter, packets) -> list:
    flows = []
    for packet in packets:
        flows.extend(meter.add_packet(packet))
    flows.extend(meter.flush_all())
    return flows


def test_tcp_flow_feature_math():
    meter = FlowMeter()
    packets = [
        tcp(BASE + 0, fwd=True, payload=0, flags=SYN, window=29200),
        tcp(BASE + 50_000, fwd=False, payload=0, flags=SYN | ACK, window=64240),
        tcp(BASE + 60_000, fwd=True, payload=100, flags=ACK | PSH),
        tcp(BASE + 70_000, fwd=False, payload=500, flags=ACK),
        tcp(BASE + 80_000, fwd=False, payload=600, flags=ACK),
    ]
    flows = collect(meter, packets)
    assert len(flows) == 1
    features = flows[0].features()

    assert features["Flow Duration"] == 80_000
    assert features["Total Fwd Packets"] == 2
    assert features["Total Backward Packets"] == 3
    assert features["Protocol"] == 6

    # forward lengths: [0, 100]
    assert features["Fwd Packet Length Mean"] == pytest.approx(50)
    assert features["Fwd Packet Length Max"] == 100
    assert features["Fwd Packet Length Min"] == 0
    assert features["Fwd Packet Length Std"] == pytest.approx(math.sqrt(5000))

    # backward lengths: [0, 500, 600] sample std (n-1)
    assert features["Bwd Packet Length Mean"] == pytest.approx(1100 / 3)
    assert features["Bwd Packet Length Max"] == 600
    assert features["Bwd Packet Length Std"] == pytest.approx(math.sqrt(103333.3333333))
    assert features["Avg Bwd Segment Size"] == pytest.approx(1100 / 3)

    # the first packet's payload is counted twice in flowLengthStats
    # values: [0, 0, 100, 0, 500, 600] -> n=6, sum=1200
    assert features["Packet Length Mean"] == pytest.approx(200)
    assert features["Packet Length Max"] == 600
    assert features["Packet Length Min"] == 0
    # Average Packet Size divides by the real packet count (5)
    assert features["Avg Packet Size"] == pytest.approx(240)

    # inter-arrival statistics
    assert features["Flow IAT Max"] == 50_000
    assert features["Fwd IAT Total"] == 60_000
    assert features["Fwd IAT Std"] == 0  # single observation
    assert features["Bwd IAT Total"] == 30_000
    assert features["Bwd IAT Std"] == pytest.approx(7071.0678118)

    # flags
    assert features["SYN Flag Count"] == 2
    assert features["ACK Flag Count"] == 4
    assert features["PSH Flag Count"] == 1
    assert features["FIN Flag Count"] == 0

    # integer down/up ratio: 3 // 2 == 1
    assert features["Down/Up Ratio"] == 1.0
    assert features["Init Fwd Win Bytes"] == 29200
    assert features["Idle Mean"] == 0

    # engineered log1p features
    assert features["FE_Log_Flow_Duration"] == pytest.approx(math.log1p(80_000))
    assert features["FE_Log_Total_Fwd_Packets"] == pytest.approx(math.log1p(2))
    assert features["FE_Log_Total_Backward_Packets"] == pytest.approx(math.log1p(3))


def test_single_packet_flow_is_dropped_like_the_java_tool():
    """The Java tool only emits flows with more than one packet on timeout."""
    meter = FlowMeter()
    meter.add_packet(tcp(BASE, fwd=True, payload=0, flags=SYN | RST))
    assert meter.flush_all() == []
    assert meter.discarded_single_packet == 1


def test_first_packet_double_count_and_average():
    meter = FlowMeter()
    packets = [
        tcp(BASE, fwd=True, payload=10, flags=ACK),
        tcp(BASE + 1000, fwd=False, payload=20, flags=ACK),
    ]
    features = collect(meter, packets)[0].features()
    # flowLengthStats: [10, 10, 20]
    assert features["Packet Length Mean"] == pytest.approx(40 / 3)
    assert features["Avg Packet Size"] == pytest.approx(20)
    assert features["Total Length of Fwd Packets"] == 10
    assert features["Total Length of Bwd Packets"] == 20


def test_flow_lifetime_splits_flows_after_120s():
    meter = FlowMeter()
    packets = [
        tcp(BASE, fwd=True, payload=5, flags=ACK),
        tcp(BASE + 1_000_000, fwd=False, payload=5, flags=ACK),
        # beyond the 120 s lifetime -> this packet starts a fresh flow
        tcp(BASE + 121_000_000, fwd=True, payload=7, flags=ACK),
        tcp(BASE + 122_000_000, fwd=False, payload=7, flags=ACK),
    ]
    flows = collect(meter, packets)
    assert len(flows) == 2
    assert flows[0].duration_us() == 1_000_000
    assert flows[1].duration_us() == 1_000_000
    assert meter.started == 2


def test_idle_gap_recorded_above_five_seconds():
    meter = FlowMeter()
    packets = [
        tcp(BASE, fwd=True, payload=1, flags=ACK),
        tcp(BASE + 6_000_000, fwd=False, payload=1, flags=ACK),
    ]
    features = collect(meter, packets)[0].features()
    assert features["Idle Max"] == 6_000_000
    assert features["Idle Mean"] == 6_000_000
    assert features["Idle Min"] == 6_000_000

    # a 4 s gap must not be recorded (threshold is 5 s)
    meter2 = FlowMeter()
    packets2 = [
        tcp(BASE, fwd=True, payload=1, flags=ACK),
        tcp(BASE + 4_000_000, fwd=False, payload=1, flags=ACK),
    ]
    features2 = collect(meter2, packets2)[0].features()
    assert features2["Idle Max"] == 0


def test_down_up_ratio_uses_integer_division():
    for fwd_pkts, bwd_pkts, expected in ((1, 3, 3.0), (5, 7, 1.0), (2, 1, 0.0)):
        meter = FlowMeter()
        packets = []
        for index in range(fwd_pkts):
            packets.append(tcp(BASE + index * 1000, fwd=True, payload=1, flags=ACK))
        for index in range(bwd_pkts):
            packets.append(tcp(BASE + 500 + index * 1000, fwd=False, payload=1, flags=ACK))
        features = collect(meter, packets)[0].features()
        assert features["Down/Up Ratio"] == expected


def test_fin_from_backward_direction_terminates_flow():
    meter = FlowMeter()
    packets = [
        tcp(BASE, fwd=True, payload=1, flags=SYN),
        tcp(BASE + 1000, fwd=False, payload=1, flags=SYN | ACK),
        tcp(BASE + 2000, fwd=False, payload=0, flags=FIN | ACK),
    ]
    emitted = []
    for packet in packets:
        emitted.extend(meter.add_packet(packet))
    assert len(emitted) == 1
    assert meter.active_flow_count() == 0


def test_udp_flow_has_no_flags_and_zero_init_window():
    meter = FlowMeter()
    packets = [udp(BASE, fwd=True, payload=40), udp(BASE + 900, fwd=False, payload=120)]
    features = collect(meter, packets)[0].features()
    assert features["Protocol"] == 17
    assert features["Init Fwd Win Bytes"] == 0
    assert features["SYN Flag Count"] == 0
    assert features["ACK Flag Count"] == 0
    assert features["Fwd Packet Length Max"] == 40
    assert features["Bwd Packet Length Max"] == 120


def test_idle_flush_emits_timed_out_flows():
    meter = FlowMeter(idle_timeout_us=30_000_000)
    meter.add_packet(tcp(BASE, fwd=True, payload=1, flags=ACK))
    meter.add_packet(tcp(BASE + 1000, fwd=False, payload=1, flags=ACK))
    # nothing idle yet
    assert meter.flush(BASE + 5_000_000) == []
    emitted = meter.flush(BASE + 40_000_000)
    assert len(emitted) == 1
    assert meter.active_flow_count() == 0


def test_selected_features_are_all_produced():
    """Train/serve contract: every feature the model consumes must exist here."""
    preprocessing = Path(__file__).resolve().parents[1] / "model_save" / "preprocessing.pkl"
    if not preprocessing.exists():
        pytest.skip("preprocessing.pkl not available")
    joblib = pytest.importorskip("joblib")

    selected = joblib.load(preprocessing)["selected_features"]

    meter = FlowMeter()
    packets = [
        tcp(BASE, fwd=True, payload=0, flags=SYN),
        tcp(BASE + 1000, fwd=False, payload=0, flags=SYN | ACK),
        tcp(BASE + 2000, fwd=True, payload=517, flags=ACK | PSH),
        tcp(BASE + 3000, fwd=False, payload=1460, flags=ACK),
        tcp(BASE + 4000, fwd=False, payload=0, flags=FIN | ACK),
    ]
    produced = collect(meter, packets)[0].features()
    missing = [name for name in selected if name not in produced]
    assert missing == [], f"features missing from the live extractor: {missing}"
    assert all(isinstance(produced[name], (int, float)) for name in selected)
