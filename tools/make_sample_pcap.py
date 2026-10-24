#!/usr/bin/env python3
"""Generate a synthetic capture file for offline validation / demos.

    venv/bin/python tools/make_sample_pcap.py tests/data/sample.pcap --seed 7

It writes a mix of benign traffic (DNS, TLS-ish handshakes, HTTP downloads)
and a few "attacker" hosts that perform port scans and flood-like bursts, so
the dashboard and the scoring pipeline have something to chew on without any
capture privileges.
"""

from __future__ import annotations

import argparse
import random
from pathlib import Path

from scapy.all import IP, TCP, UDP, DNS, DNSQR, Ether, Raw, wrpcap

BASE_TS = 1_760_000_000.0  # fixed epoch so runs are reproducible

BENIGN_HOSTS = [f"192.168.1.{ip}" for ip in (20, 21, 22, 23, 30, 31)]
ATTACKERS = ["203.0.113.66", "198.51.100.9"]
DNS_SERVERS = ["192.168.1.1", "9.9.9.9"]
GATEWAY = "192.168.1.1"
WAN_IP = "203.0.113.10"


def dns_exchange(ts: float, client: str, name: str) -> list:
    sport = random.randint(30000, 60000)
    query = IP(src=client, dst=random.choice(DNS_SERVERS)) / UDP(sport=sport, dport=53) / DNS(
        rd=1, qd=DNSQR(qname=name)
    )
    reply = IP(src=query[IP].dst, dst=client) / UDP(sport=53, dport=sport) / DNS(
        id=query[DNS].id, qr=1, qd=DNSQR(qname=name), an=DNSQR(qname=name)
    )
    query.time = ts
    reply.time = ts + random.uniform(0.01, 0.08)
    return [query, reply]


def http_conversation(ts: float, client: str, server: str, size: int, sport: int) -> list:
    seq_c, seq_s = 1000, 5000
    packets = [
        IP(src=client, dst=server) / TCP(sport=sport, dport=443, flags="S", seq=seq_c, window=29200),
        IP(src=server, dst=client)
        / TCP(sport=443, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1, window=64240),
        IP(src=client, dst=server) / TCP(sport=sport, dport=443, flags="A", seq=seq_c + 1, ack=seq_s + 1),
    ]
    cursor = ts + 0.002
    seq_c += 1
    seq_s += 1
    request = IP(src=client, dst=server) / TCP(
        sport=sport, dport=443, flags="PA", seq=seq_c, ack=seq_s, window=501
    ) / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
    request.time = cursor
    packets.append(request)
    cursor += 0.05
    seq_c += len(bytes(request[Raw]))

    remaining = size
    while remaining > 0:
        chunk = min(1400, remaining)
        segment = IP(src=server, dst=client) / TCP(
            sport=443, dport=sport, flags="PA", seq=seq_s, ack=seq_c, window=64240
        ) / Raw(bytes(chunk))
        segment.time = cursor
        packets.append(segment)
        cursor += random.uniform(0.005, 0.03)
        seq_s += chunk
        remaining -= chunk
        ack = IP(src=client, dst=server) / TCP(
            sport=sport, dport=443, flags="A", seq=seq_c, ack=seq_s, window=501
        )
        ack.time = cursor - 0.001
        packets.append(ack)

    for src, dst, flags, seq, ack, port in (
        (client, server, "FA", seq_c, seq_s, sport),
        (server, client, "FA", seq_s, seq_c, 443),
    ):
        fin = IP(src=src, dst=dst) / TCP(
            sport=port, dport=443 if src == client else sport, flags=flags, seq=seq, ack=ack
        )
        fin.time = cursor
        packets.append(fin)
        cursor += 0.01
    return packets


def port_scan(ts: float, attacker: str, target: str, ports: list[int]) -> list:
    packets = []
    moment = ts
    for port in ports:
        syn = IP(src=attacker, dst=target) / TCP(
            sport=random.randint(40000, 60000), dport=port, flags="S", seq=random.randint(1, 2**31)
        )
        syn.time = moment
        packets.append(syn)
        rst = IP(src=target, dst=attacker) / TCP(
            sport=port, dport=syn[TCP].sport, flags="RA", seq=0, ack=syn[TCP].seq + 1
        )
        rst.time = moment + 0.001
        packets.append(rst)
        moment += random.uniform(0.01, 0.05)
    return packets


def flood(ts: float, attacker: str, target: str, port: int, count: int) -> list:
    packets = []
    moment = ts
    sport = random.randint(1024, 60000)
    for _ in range(count):
        packet = IP(src=attacker, dst=target) / TCP(
            sport=sport, dport=port, flags="S", seq=random.randint(1, 2**31)
        )
        packet.time = moment
        packets.append(packet)
        moment += random.uniform(0.0005, 0.005)
    return packets


def build(seed: int, rounds: int, base_ts: float | None = None) -> list:
    random.seed(seed)
    packets: list = []
    moment = BASE_TS if base_ts is None else base_ts

    for _ in range(rounds):
        for client in random.sample(BENIGN_HOSTS, k=3):
            packets += dns_exchange(moment, client, f"host{random.randint(1, 40)}.example.com")
        packets += http_conversation(
            moment + 0.2, random.choice(BENIGN_HOSTS), WAN_IP, random.randint(2000, 60000), random.randint(30000, 50000)
        )
        # a scan and a small flood every other round
        if _ % 2 == 0:
            packets += port_scan(moment + 0.4, random.choice(ATTACKERS), GATEWAY, random.sample(range(1, 1024), 12))
        else:
            packets += flood(moment + 0.4, random.choice(ATTACKERS), GATEWAY, random.choice([22, 80, 443]), 25)
        moment += 1.0

    packets.sort(key=lambda pkt: pkt.time)
    return packets


def main() -> int:
    import time
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", default="tests/data/sample.pcap")
    parser.add_argument("--seed", type=int, default=7)
    parser.add_argument("--rounds", type=int, default=12, help="seconds of synthetic activity")
    parser.add_argument("--now", action="store_true", help="use current epoch as base timestamp")
    args = parser.parse_args()

    base_ts = time.time() if args.now else BASE_TS
    packets = build(args.seed, args.rounds, base_ts=base_ts)
    # wrap in Ethernet so the resulting pcap has a link type every tool knows
    frames = [Ether(src="aa:bb:cc:00:00:01", dst="aa:bb:cc:00:00:02") / pkt for pkt in packets]
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(output), frames)
    print(f"wrote {len(frames)} packets to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
