"""In-memory rolling counters that feed the dashboard charts."""

from __future__ import annotations

import threading
import time
from collections import deque


class Stats:
    """Per-second buckets kept in memory for the live charts.

    Only aggregate numbers are kept here; per-flow detail lives in SQLite.
    """

    def __init__(self, history_s: int = 180) -> None:
        self.history_s = history_s
        self._lock = threading.Lock()
        self._buckets: dict[int, dict] = {}
        self.started_at = time.time()
        self.packets_total = 0
        self.bytes_total = 0
        self.flows_total = 0
        self.attacks_total = 0
        self.dropped_packets = 0
        self.parse_errors = 0
        self.last_flow_ts = 0.0
        self.last_attack_ts = 0.0
        self.verdicts = {"BENIGN": 0, "ATTACK": 0}
        self.proto_counters = {6: 0, 17: 0}
        self._recent_packet_times = deque(maxlen=20000)

    # -- ingestion -----------------------------------------------------------
    @staticmethod
    def _bucket(ts: float) -> int:
        return int(ts)

    def _slot(self, ts: float) -> dict:
        key = self._bucket(ts)
        slot = self._buckets.get(key)
        if slot is None:
            slot = {
                "ts": key,
                "packets": 0,
                "bytes": 0,
                "flows": 0,
                "attacks": 0,
                "fwd_bytes": 0,
                "bwd_bytes": 0,
            }
            self._buckets[key] = slot
            cutoff = key - self.history_s
            for old in [k for k in self._buckets if k < cutoff]:
                del self._buckets[old]
        return slot

    def record_packet(self, ts: float, wire_len: int, proto: int) -> None:
        with self._lock:
            slot = self._slot(ts)
            slot["packets"] += 1
            slot["bytes"] += wire_len
            self.packets_total += 1
            self.bytes_total += wire_len
            self.proto_counters[proto] = self.proto_counters.get(proto, 0) + 1
            self._recent_packet_times.append(ts)

    def record_flow(self, verdict: str, fwd_bytes: float, bwd_bytes: float, ts: float | None = None) -> None:
        ts = time.time() if ts is None else ts
        with self._lock:
            slot = self._slot(ts)
            slot["flows"] += 1
            slot["fwd_bytes"] += fwd_bytes or 0
            slot["bwd_bytes"] += bwd_bytes or 0
            self.flows_total += 1
            self.last_flow_ts = ts
            self.verdicts[verdict] = self.verdicts.get(verdict, 0) + 1
            if verdict == "ATTACK":
                slot["attacks"] += 1
                self.attacks_total += 1
                self.last_attack_ts = ts

    def record_drop(self, count: int = 1) -> None:
        with self._lock:
            self.dropped_packets += count

    def record_parse_error(self) -> None:
        with self._lock:
            self.parse_errors += 1

    # -- reporting -----------------------------------------------------------
    def rates(self) -> dict:
        """Packets/s and bytes/s over the last few seconds."""
        now = time.time()
        window = 5.0
        with self._lock:
            times = [t for t in self._recent_packet_times if t >= now - window]
        span = max(1.0, min(window, now - self.started_at))
        return {
            "packets_per_s": len(times) / span,
            "bytes_per_s": self._bytes_in_window(window) / span,
        }

    def _bytes_in_window(self, window: float) -> float:
        cutoff = time.time() - window
        return float(sum(b["bytes"] for b in self._buckets.values() if b["ts"] >= cutoff))

    def timeseries(self, points: int = 120) -> dict:
        now = int(time.time())
        start = now - points + 1
        labels, packets, byts, flows, attacks = [], [], [], [], []
        with self._lock:
            for ts in range(start, now + 1):
                bucket = self._buckets.get(ts, {})
                labels.append(ts)
                packets.append(bucket.get("packets", 0))
                byts.append(bucket.get("bytes", 0))
                flows.append(bucket.get("flows", 0))
                attacks.append(bucket.get("attacks", 0))
        return {
            "labels": labels,
            "packets": packets,
            "bytes": byts,
            "flows": flows,
            "attacks": attacks,
        }

    def snapshot(self, *, active_flows: int = 0, mode: str = "", backend: str = "") -> dict:
        with self._lock:
            verdicts = dict(self.verdicts)
            data = {
                "uptime_s": int(time.time() - self.started_at),
                "packets_total": self.packets_total,
                "bytes_total": self.bytes_total,
                "flows_total": self.flows_total,
                "attacks_total": self.attacks_total,
                "dropped_packets": self.dropped_packets,
                "parse_errors": self.parse_errors,
                "active_flows": active_flows,
                "verdicts": verdicts,
                "protocols": {str(k): v for k, v in self.proto_counters.items()},
            }
        data.update(self.rates())
        data["mode"] = mode
        data["backend"] = backend
        return data
