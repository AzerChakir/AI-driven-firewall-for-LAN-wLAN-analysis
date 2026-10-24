#!/usr/bin/env python3
"""
Attack Simulation Test Script
==============================
Simulates real attack traffic patterns against the local machine
to verify the AI model correctly classifies them as ATTACK.

Attacks simulated:
  1. SYN Port Scan       – rapid SYN packets to many ports (like nmap -sS)
  2. SYN Flood (DoS)     – many SYN packets to same port, no replies
  3. SSH Brute Force     – many small TCP flows to port 22
  4. FTP Brute Force     – many small TCP flows to port 21

Run as root (needs raw sockets):
    sudo venv/bin/python test_attack_simulation.py
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.request

TARGET = "127.0.0.1"   # attack ourselves (safe, loopback)
DASHBOARD = "http://localhost:8080"


def api(path: str) -> dict:
    with urllib.request.urlopen(f"{DASHBOARD}{path}", timeout=5) as r:
        return json.loads(r.read())


def wait_for_server() -> bool:
    for _ in range(10):
        try:
            api("/api/health")
            return True
        except Exception:
            time.sleep(1)
    return False


def snapshot() -> dict:
    try:
        s = api("/api/summary")
        return {
            "flows": s["stats"]["flows_total"],
            "attacks": s["stats"]["attacks_total"],
            "packets": s["stats"]["packets_total"],
        }
    except Exception:
        return {"flows": 0, "attacks": 0, "packets": 0}


def recent_attacks(limit: int = 20) -> list:
    try:
        alerts = api(f"/api/alerts?limit={limit}")
        return alerts.get("alerts", [])
    except Exception:
        return []


# ── Attack generators ────────────────────────────────────────────────────────

def syn_port_scan(target: str, ports: int = 100) -> None:
    """Rapid SYN to many consecutive ports — classic nmap -sS fingerprint."""
    from scapy.all import IP, TCP, send
    print(f"  → Sending SYN scan to {target} ({ports} ports)...")
    pkts = [
        IP(dst=target) / TCP(dport=p, flags="S", sport=12345 + p % 1000)
        for p in range(1, ports + 1)
    ]
    send(pkts, verbose=False)


def syn_flood(target: str, port: int = 80, count: int = 200) -> None:
    """SYN flood DoS — many SYN packets from random sources to one port."""
    import random
    from scapy.all import IP, TCP, send
    print(f"  → Sending SYN flood to {target}:{port} ({count} packets)...")
    pkts = [
        IP(dst=target, src=f"10.0.{random.randint(1,254)}.{random.randint(1,254)}") /
        TCP(dport=port, flags="S", sport=random.randint(1024, 65535))
        for _ in range(count)
    ]
    send(pkts, verbose=False)


def brute_force_ssh(target: str, attempts: int = 60) -> None:
    """Simulate SSH brute force: many short TCP flows to port 22."""
    import random
    from scapy.all import IP, TCP, send
    print(f"  → Simulating SSH brute force on {target}:22 ({attempts} attempts)...")
    pkts = []
    for _ in range(attempts):
        sport = random.randint(30000, 60000)
        src = f"203.0.113.{random.randint(1,254)}"   # TEST-NET-3 (RFC 5737)
        # SYN
        pkts.append(IP(dst=target, src=src) / TCP(dport=22, sport=sport, flags="S"))
        # ACK (fake handshake)
        pkts.append(IP(dst=target, src=src) / TCP(dport=22, sport=sport, flags="A", seq=1))
        # RST (connection rejected)
        pkts.append(IP(dst=target, src=src) / TCP(dport=22, sport=sport, flags="R", seq=2))
    send(pkts, verbose=False)


def ftp_brute_force(target: str, attempts: int = 50) -> None:
    """Simulate FTP brute force: many short TCP flows to port 21."""
    import random
    from scapy.all import IP, TCP, send
    print(f"  → Simulating FTP brute force on {target}:21 ({attempts} attempts)...")
    pkts = []
    for _ in range(attempts):
        sport = random.randint(30000, 60000)
        src = f"198.51.100.{random.randint(1,254)}"   # TEST-NET-2 (RFC 5737)
        pkts.append(IP(dst=target, src=src) / TCP(dport=21, sport=sport, flags="S"))
        pkts.append(IP(dst=target, src=src) / TCP(dport=21, sport=sport, flags="A", seq=1))
        pkts.append(IP(dst=target, src=src) / TCP(dport=21, sport=sport, flags="R", seq=2))
    send(pkts, verbose=False)


# ── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    global DASHBOARD
    parser = argparse.ArgumentParser(description="Attack simulation test")
    parser.add_argument("--target", default=TARGET)
    parser.add_argument("--dashboard", default=DASHBOARD)
    args = parser.parse_args()

    DASHBOARD = args.dashboard

    print("=" * 60)
    print("  AI FIREWALL — ATTACK DETECTION TEST")
    print("=" * 60)

    # Check server is up
    print("\n[1] Checking dashboard is reachable...")
    if not wait_for_server():
        print("  ✗ Dashboard not reachable at", DASHBOARD)
        print("    Start the server first:")
        print("    sudo venv/bin/python run.py --port 8080 --iface lo --mode monitor")
        sys.exit(1)
    print("  ✓ Dashboard online")

    # Baseline
    before = snapshot()
    print(f"\n[2] Baseline: flows={before['flows']}  attacks={before['attacks']}  packets={before['packets']}")

    # ── Run attacks ──
    print("\n[3] Launching attack simulations...")
    print()

    syn_port_scan(args.target, ports=120)
    time.sleep(2)

    syn_flood(args.target, port=80, count=250)
    time.sleep(2)

    brute_force_ssh(args.target, attempts=80)
    time.sleep(2)

    ftp_brute_force(args.target, attempts=60)
    time.sleep(2)

    # Wait for flows to be emitted + scored (idle timeout = 5s)
    print("\n[4] Waiting for flow meter to emit & AI model to score (12s)...")
    for remaining in range(12, 0, -1):
        print(f"    {remaining}s remaining...", end="\r", flush=True)
        time.sleep(1)
    print()

    # Results
    after = snapshot()
    new_flows = after['flows'] - before['flows']
    new_attacks = after['attacks'] - before['attacks']
    new_packets = after['packets'] - before['packets']

    print("\n" + "=" * 60)
    print("  RESULTS")
    print("=" * 60)
    print(f"  New packets captured : {new_packets:,}")
    print(f"  New flows scored     : {new_flows}")
    print(f"  Flows flagged ATTACK : {new_attacks}")
    if new_flows > 0:
        pct = round(new_attacks / new_flows * 100, 1)
        print(f"  Detection rate       : {pct}%")

    print()
    print("  Latest ATTACK alerts:")
    alerts = recent_attacks(30)
    attack_alerts = [a for a in alerts if a.get("verdict") == "ATTACK" or a.get("action") in ("alert", "blocked")]
    if attack_alerts:
        for a in attack_alerts[:10]:
            t = time.strftime("%H:%M:%S", time.localtime(a["ts"]))
            print(f"    [{t}] {a['src_ip']} -> {a['dst_ip']}:{a['dst_port']}  score={a['score']:.3f}  action={a['action']}")
    else:
        print("    (none yet — flows may still be scoring, check the dashboard)")

    print()
    if new_attacks > 0:
        print("  ✅ MODEL WORKS — Attack traffic successfully detected!")
    else:
        print("  ⚠️  No attacks detected yet.")
        print("     → Check dashboard in ~10s, flows may still be processing")
        print("     → Or run again with: sudo venv/bin/python test_attack_simulation.py")

    print("=" * 60)
    print(f"  Dashboard: {DASHBOARD}/")
    print("=" * 60)


if __name__ == "__main__":
    main()

