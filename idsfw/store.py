"""SQLite persistence for flows, alerts, blocked addresses and settings."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Optional

log = logging.getLogger("idsfw.store")

SCHEMA = """
CREATE TABLE IF NOT EXISTS flows (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    src_ip      TEXT NOT NULL,
    src_port    INTEGER,
    dst_ip      TEXT NOT NULL,
    dst_port    INTEGER,
    proto       INTEGER,
    duration_us INTEGER,
    fwd_pkts    INTEGER,
    bwd_pkts    INTEGER,
    fwd_bytes   REAL,
    bwd_bytes   REAL,
    score       REAL,
    verdict     TEXT,
    service     TEXT
);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts);
CREATE INDEX IF NOT EXISTS idx_flows_src ON flows(src_ip);
CREATE INDEX IF NOT EXISTS idx_flows_verdict ON flows(verdict);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    src_ip      TEXT NOT NULL,
    dst_ip      TEXT,
    dst_port    INTEGER,
    proto       INTEGER,
    score       REAL,
    verdict     TEXT,
    action      TEXT,
    reason      TEXT
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS blocks (
    ip          TEXT PRIMARY KEY,
    ts          REAL NOT NULL,
    source      TEXT NOT NULL,
    expires_ts  REAL,
    note        TEXT
);

CREATE TABLE IF NOT EXISTS settings (
    key         TEXT PRIMARY KEY,
    value       TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS counters (
    key         TEXT PRIMARY KEY,
    value       REAL NOT NULL
);
"""


class Store:
    def __init__(self, path: str | Path, max_flows: int = 5000, max_alerts: int = 2000) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.max_flows = max_flows
        self.max_alerts = max_alerts
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        with self._lock:
            self._conn.executescript("PRAGMA journal_mode=WAL;")
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    # -- low level -----------------------------------------------------------
    def _execute(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            self._conn.commit()
            return cur

    def _query(self, sql: str, params: Iterable[Any] = ()) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(sql, tuple(params)).fetchall()
        return [dict(row) for row in rows]

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # -- flows ---------------------------------------------------------------
    def insert_flows(self, rows: list[dict]) -> None:
        if not rows:
            return
        with self._lock:
            self._conn.executemany(
                """INSERT INTO flows (ts, src_ip, src_port, dst_ip, dst_port, proto,
                       duration_us, fwd_pkts, bwd_pkts, fwd_bytes, bwd_bytes,
                       score, verdict, service)
                   VALUES (:ts, :src_ip, :src_port, :dst_ip, :dst_port, :proto,
                       :duration_us, :fwd_pkts, :bwd_pkts, :fwd_bytes, :bwd_bytes,
                       :score, :verdict, :service)""",
                rows,
            )
            self._conn.execute(
                "DELETE FROM flows WHERE id <= (SELECT MAX(id) FROM flows) - ?",
                (self.max_flows,),
            )
            self._conn.commit()

    def recent_flows(self, limit: int = 50, verdict: Optional[str] = None) -> list[dict]:
        if verdict:
            return self._query(
                "SELECT * FROM flows WHERE verdict = ? ORDER BY id DESC LIMIT ?", (verdict, limit)
            )
        return self._query("SELECT * FROM flows ORDER BY id DESC LIMIT ?", (limit,))

    def flow_totals(self) -> dict:
        rows = self._query("SELECT verdict, COUNT(*) AS n FROM flows GROUP BY verdict")
        totals = {"BENIGN": 0, "ATTACK": 0}
        for row in rows:
            totals[row["verdict"] or "BENIGN"] = row["n"]
        return totals

    def top_talkers(self, window_s: int = 300, limit: int = 10) -> list[dict]:
        cutoff = time.time() - window_s
        return self._query(
            """SELECT src_ip,
                      SUM(fwd_bytes + bwd_bytes) AS bytes,
                      COUNT(*) AS flows,
                      SUM(CASE WHEN verdict = 'ATTACK' THEN 1 ELSE 0 END) AS attacks
               FROM flows WHERE ts >= ?
               GROUP BY src_ip ORDER BY bytes DESC LIMIT ?""",
            (cutoff, limit),
        )

    def top_attackers(self, window_s: int = 300, limit: int = 10) -> list[dict]:
        cutoff = time.time() - window_s
        return self._query(
            """SELECT src_ip, COUNT(*) AS attacks, MAX(score) AS score
               FROM flows WHERE ts >= ? AND verdict = 'ATTACK'
               GROUP BY src_ip ORDER BY attacks DESC LIMIT ?""",
            (cutoff, limit),
        )

    def protocol_breakdown(self, window_s: int = 300) -> list[dict]:
        cutoff = time.time() - window_s
        return self._query(
            """SELECT proto, COUNT(*) AS flows,
                      SUM(CASE WHEN verdict = 'ATTACK' THEN 1 ELSE 0 END) AS attacks
               FROM flows WHERE ts >= ? GROUP BY proto ORDER BY flows DESC""",
            (cutoff,),
        )

    def destination_ports(self, window_s: int = 300, limit: int = 10) -> list[dict]:
        cutoff = time.time() - window_s
        return self._query(
            """SELECT dst_port, COUNT(*) AS flows,
                      SUM(CASE WHEN verdict = 'ATTACK' THEN 1 ELSE 0 END) AS attacks
               FROM flows WHERE ts >= ? AND dst_port IS NOT NULL
               GROUP BY dst_port ORDER BY flows DESC LIMIT ?""",
            (cutoff, limit),
        )

    # -- alerts --------------------------------------------------------------
    def insert_alert(self, alert: dict) -> None:
        with self._lock:
            self._conn.execute(
                """INSERT INTO alerts (ts, src_ip, dst_ip, dst_port, proto, score,
                       verdict, action, reason)
                   VALUES (:ts, :src_ip, :dst_ip, :dst_port, :proto, :score,
                       :verdict, :action, :reason)""",
                alert,
            )
            self._conn.execute(
                "DELETE FROM alerts WHERE id <= (SELECT MAX(id) FROM alerts) - ?",
                (self.max_alerts,),
            )
            self._conn.commit()

    def recent_alerts(self, limit: int = 50) -> list[dict]:
        return self._query("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))

    def alert_counts(self, window_s: int = 300) -> dict:
        cutoff = time.time() - window_s
        row = self._query(
            "SELECT COUNT(*) AS n FROM alerts WHERE ts >= ? AND verdict = 'ATTACK'", (cutoff,)
        )
        total = self._query("SELECT COUNT(*) AS n FROM alerts WHERE verdict = 'ATTACK'")
        return {"window": row[0]["n"] if row else 0, "total": total[0]["n"] if total else 0}

    # -- blocks --------------------------------------------------------------
    def add_block(self, ip: str, source: str, expires_ts: float | None, note: str = "") -> None:
        self._execute(
            """INSERT INTO blocks (ip, ts, source, expires_ts, note)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(ip) DO UPDATE SET ts=excluded.ts, source=excluded.source,
                   expires_ts=excluded.expires_ts, note=excluded.note""",
            (ip, time.time(), source, expires_ts, note),
        )

    def remove_block(self, ip: str) -> None:
        self._execute("DELETE FROM blocks WHERE ip = ?", (ip,))

    def list_blocks(self) -> list[dict]:
        return self._query("SELECT * FROM blocks ORDER BY ts DESC")

    def block_exists(self, ip: str) -> bool:
        return bool(self._query("SELECT 1 FROM blocks WHERE ip = ?", (ip,)))

    def expired_blocks(self, now: float | None = None) -> list[dict]:
        now = time.time() if now is None else now
        return self._query(
            "SELECT * FROM blocks WHERE expires_ts IS NOT NULL AND expires_ts <= ?", (now,)
        )

    # -- settings / counters -------------------------------------------------
    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        rows = self._query("SELECT value FROM settings WHERE key = ?", (key,))
        return rows[0]["value"] if rows else default

    def set_setting(self, key: str, value: str) -> None:
        self._execute(
            """INSERT INTO settings (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
            (key, value),
        )

    def get_counter(self, key: str, default: float = 0.0) -> float:
        rows = self._query("SELECT value FROM counters WHERE key = ?", (key,))
        return float(rows[0]["value"]) if rows else default

    def set_counter(self, key: str, value: float) -> None:
        self._execute(
            """INSERT INTO counters (key, value) VALUES (?, ?)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
            (key, float(value)),
        )

    def reset_data(self) -> None:
        with self._lock:
            self._conn.executescript("DELETE FROM flows; DELETE FROM alerts;")
            self._conn.commit()

    @staticmethod
    def dumps(value: Any) -> str:  # pragma: no cover - convenience
        return json.dumps(value, default=str)
