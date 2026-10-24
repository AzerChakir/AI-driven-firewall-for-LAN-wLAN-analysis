"""Service orchestrator: wires capture -> flow meter -> inference -> store/firewall."""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections import defaultdict, deque
from typing import Optional

from . import capture as capture_mod
from .config import Config
from .firewall import Firewall
from .flowmeter import FlowMeter, PacketRec
from .inference import Predictor
from .stats import Stats
from .store import Store

log = logging.getLogger("idsfw.service")

# Well-known ports used only for a friendly "service" label in the dashboard.
SERVICE_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    67: "dhcp",
    68: "dhcp",
    80: "http",
    110: "pop3",
    123: "ntp",
    143: "imap",
    161: "snmp",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    514: "syslog",
    587: "smtp",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    1194: "openvpn",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    3306: "mysql",
    3389: "rdp",
    5432: "postgres",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    27017: "mongodb",
}


def service_name(dst_port: int | None) -> str:
    if dst_port is None:
        return "-"
    if dst_port in SERVICE_PORTS:
        return SERVICE_PORTS[dst_port]
    if dst_port > 1024:
        return "unknown"
    return str(dst_port)


class IdsService:
    """Owns every runtime component and the worker threads."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.store = Store(
            cfg.get("store.path", "data/idsfw.db"),
            max_flows=int(cfg.get("store.max_flows", 5000)),
            max_alerts=int(cfg.get("store.max_alerts", 2000)),
        )
        self.stats = Stats()
        self.predictor = Predictor(
            cfg.get("model.dir", "model_save"),
            threshold=cfg.get("model.threshold"),
        )
        self.flowmeter = FlowMeter(
            flow_timeout_us=int(float(cfg.get("flows.timeout_s", 120)) * 1_000_000),
            idle_timeout_us=int(float(cfg.get("flows.idle_timeout_s", 5)) * 1_000_000),
            active_timeout_us=int(float(cfg.get("flows.active_timeout_s", 10)) * 1_000_000)
            if cfg.get("flows.active_timeout_s")
            else None,
            min_packets=int(cfg.get("flows.min_packets", 1)),
        )
        self.firewall = Firewall(
            table=cfg.get("firewall.nft_table", "idsfw"),
            allowlist=cfg.get("firewall.allowlist", []),
        )
        self.mode = self.store.get_setting("firewall_mode", cfg.get("firewall.mode", "manual"))

        self.packet_queue: queue.Queue[PacketRec] = queue.Queue(
            maxsize=int(cfg.get("capture.queue_size", 200000))
        )
        self.flow_queue: queue.Queue[dict] = queue.Queue()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._capture: Optional[capture_mod.LiveCapture] = None
        self._attack_history: dict[str, deque[float]] = defaultdict(deque)
        self._block_lock = threading.Lock()
        self.source = "live"
        self.interface = cfg.get("capture.interface", "auto")
        self.pcap_path: str | None = None
        self.replay_done = False
        self.runtime_blocking = self._blocking_available()

    def _blocking_available(self) -> bool:
        """Blocking requires both nftables and a real trained model."""
        if self.predictor.backend == "mock":
            log.error("firewall blocking disabled: no usable trained model backend")
            return False
        return self.firewall.available()

    # -- lifecycle -----------------------------------------------------------
    def start(self, pcap: Optional[str] = None) -> None:
        self.pcap_path = pcap
        self.source = "pcap" if pcap else "live"
        self.runtime_blocking = bool(not pcap and self._blocking_available())

        if not pcap and self.mode != "monitor" and self.firewall.available():
            if self.firewall.ensure_table():
                self.firewall.restore(self.store.list_blocks())

        self._spawn("meter", self._meter_loop)
        self._spawn("scoring", self._scoring_loop)
        self._spawn("maintenance", self._maintenance_loop)

        if pcap:
            self._spawn("replay", self._replay_loop)
        else:
            interface = self.cfg.get("capture.interface", "auto")
            from .netinfo import detect_capture_interface

            resolved = detect_capture_interface(interface)
            if not resolved:
                raise RuntimeError("could not determine a capture interface")
            self.interface = resolved
            callback = capture_mod.make_queue_callback(
                self.packet_queue,
                on_drop=self.stats.record_drop,
                on_error=self.stats.record_parse_error,
            )
            self._capture = capture_mod.LiveCapture(
                interface=resolved,
                bpf_filter=self.cfg.get("capture.bpf_filter", "ip and (tcp or udp)"),
                snaplen=int(self.cfg.get("capture.snaplen", 256)),
                promiscuous=bool(self.cfg.get("capture.promiscuous", True)),
                callback=callback,
            )
            self._capture.start()

    def stop(self) -> None:
        self._stop.set()
        if self._capture is not None:
            self._capture.stop()
        for thread in self._threads:
            thread.join(timeout=5)

    def wait(self) -> None:
        while not self._stop.is_set():
            time.sleep(0.5)

    def _spawn(self, name: str, target) -> None:
        thread = threading.Thread(target=target, name=f"idsfw-{name}", daemon=True)
        thread.start()
        self._threads.append(thread)

    # -- workers -------------------------------------------------------------
    def _replay_loop(self) -> None:
        callback = capture_mod.make_queue_callback(
            self.packet_queue, on_drop=self.stats.record_drop, on_error=self.stats.record_parse_error
        )
        realtime = bool(self.cfg.get("capture.realtime_replay", False))
        speed = float(self.cfg.get("capture.replay_speed", 1.0))
        capture_mod.replay_pcap(self.pcap_path, callback, realtime=realtime, speed=speed)
        # drain the meter, then force-emit everything still open
        while not self._stop.is_set():
            if self.packet_queue.empty():
                break
            time.sleep(0.05)
        time.sleep(0.2)
        for flow in self.flowmeter.flush_all():
            self._emit_flow(flow)
        # let the scoring worker finish
        while not self._stop.is_set() and not self.flow_queue.empty():
            time.sleep(0.1)
        self.replay_done = True

    def _meter_loop(self) -> None:
        last_flush = time.time()
        while not self._stop.is_set():
            try:
                record = self.packet_queue.get(timeout=0.25)
            except queue.Empty:
                record = None

            if record is not None:
                self.stats.record_packet(record.ts_us / 1e6, record.wire_len, record.proto)
                try:
                    for flow in self.flowmeter.add_packet(record):
                        self._emit_flow(flow)
                except Exception:  # a broken flow must not kill the pipeline
                    log.exception("flow meter error")

            now = time.time()
            if now - last_flush >= 0.5:
                last_flush = now
                for flow in self.flowmeter.flush(int(now * 1_000_000)):
                    self._emit_flow(flow)

    def _emit_flow(self, flow) -> None:
        row = {
            "ts": flow.last_ts / 1e6,
            "src_ip": flow.src_ip,
            "src_port": flow.src_port,
            "dst_ip": flow.dst_ip,
            "dst_port": flow.dst_port,
            "proto": flow.proto,
            "duration_us": flow.duration_us(),
            "fwd_pkts": flow.fwd_n,
            "bwd_pkts": flow.bwd_n,
            "fwd_bytes": float(flow.fwd_len.get_sum() or 0),
            "bwd_bytes": float(flow.bwd_len.get_sum() or 0),
            "service": service_name(flow.dst_port),
            "features": flow.features(),
        }
        self.flow_queue.put(row)

    def _scoring_loop(self) -> None:
        batch_size = int(self.cfg.get("model.batch_size", 64))
        interval = float(self.cfg.get("model.batch_interval_s", 1.0))
        pending: list[dict] = []
        last_flush = time.time()

        def flush() -> None:
            nonlocal pending
            if not pending:
                return
            rows = pending
            pending = []
            # Skip scoring for flows where both endpoints are allowlisted
            # (e.g. local multicast/broadcast) or where the initiating IP
            # is in the trusted CDN/cloud allowlist — these cannot be threats.
            scoreable = [
                r for r in rows
                if not (
                    self.firewall.is_allowlisted(r["src_ip"])
                    and self.firewall.is_allowlisted(r["dst_ip"])
                )
            ]
            skipped = len(rows) - len(scoreable)
            if skipped:
                log.debug("skipped scoring %d allowlisted flows", skipped)
                # Record them as BENIGN in stats without hitting the model
                for r in rows:
                    if self.firewall.is_allowlisted(r["src_ip"]) and self.firewall.is_allowlisted(r["dst_ip"]):
                        self.stats.record_flow("BENIGN", r["fwd_bytes"], r["bwd_bytes"], ts=r["ts"] or time.time())
            if not scoreable:
                self.store.insert_flows([
                    {
                        "ts": time.time(),
                        "src_ip": r["src_ip"], "src_port": r["src_port"],
                        "dst_ip": r["dst_ip"], "dst_port": r["dst_port"],
                        "proto": r["proto"], "duration_us": r["duration_us"],
                        "fwd_pkts": r["fwd_pkts"], "bwd_pkts": r["bwd_pkts"],
                        "fwd_bytes": r["fwd_bytes"], "bwd_bytes": r["bwd_bytes"],
                        "score": 0.0, "verdict": "BENIGN", "service": r["service"],
                    }
                    for r in rows
                ])
                return
            try:
                predictions = self.predictor.predict_rows([r["features"] for r in scoreable])
            except Exception:
                log.exception("inference failed")
                return
            self._commit(scoreable, predictions)
            # Store the skipped allowlisted rows as BENIGN flows (no alert)
            if skipped:
                self.store.insert_flows([
                    {
                        "ts": time.time(),
                        "src_ip": r["src_ip"], "src_port": r["src_port"],
                        "dst_ip": r["dst_ip"], "dst_port": r["dst_port"],
                        "proto": r["proto"], "duration_us": r["duration_us"],
                        "fwd_pkts": r["fwd_pkts"], "bwd_pkts": r["bwd_pkts"],
                        "fwd_bytes": r["fwd_bytes"], "bwd_bytes": r["bwd_bytes"],
                        "score": 0.0, "verdict": "BENIGN", "service": r["service"],
                    }
                    for r in rows
                    if self.firewall.is_allowlisted(r["src_ip"]) and self.firewall.is_allowlisted(r["dst_ip"])
                ])

        while not self._stop.is_set():
            try:
                row = self.flow_queue.get(timeout=0.1)
                pending.append(row)
            except queue.Empty:
                pass
            now = time.time()
            if len(pending) >= batch_size or (pending and now - last_flush >= interval):
                flush()
                last_flush = now
        flush()

    def _commit(self, rows: list[dict], predictions) -> None:
        store_rows = []
        alerts = []
        for row, prediction in zip(rows, predictions):
            self.stats.record_flow(
                prediction.label, row["fwd_bytes"], row["bwd_bytes"], ts=row["ts"] or time.time()
            )
            store_rows.append(
                {
                    "ts": time.time(),
                    "src_ip": row["src_ip"],
                    "src_port": row["src_port"],
                    "dst_ip": row["dst_ip"],
                    "dst_port": row["dst_port"],
                    "proto": row["proto"],
                    "duration_us": row["duration_us"],
                    "fwd_pkts": row["fwd_pkts"],
                    "bwd_pkts": row["bwd_pkts"],
                    "fwd_bytes": row["fwd_bytes"],
                    "bwd_bytes": row["bwd_bytes"],
                    "score": prediction.score,
                    "verdict": prediction.label,
                    "service": row["service"],
                }
            )
            if prediction.label == "ATTACK":
                alerts.append((row, prediction))

        self.store.insert_flows(store_rows)
        for row, prediction in alerts:
            self._handle_attack(row, prediction)

    def _handle_attack(self, row: dict, prediction) -> None:
        initiator = row["src_ip"]
        responder = row["dst_ip"]

        # Suppress alerts for flows where either endpoint is a trusted CDN /
        # cloud IP — these are almost certainly false positives caused by the
        # CIC-IDS2017 model not having seen real HTTPS traffic to major CDNs.
        if self.firewall.is_allowlisted(initiator) or self.firewall.is_allowlisted(responder):
            log.debug(
                "suppressed alert for allowlisted flow %s -> %s (score=%.3f)",
                initiator, responder, prediction.score,
            )
            return

        action = "alert"
        reason = f"model score {prediction.score:.3f} >= {prediction.threshold:.2f}"

        if self.mode == "auto" and not self.firewall.is_allowlisted(initiator):
            if self._should_auto_block(initiator):
                ok, _ = self._block(initiator, source="auto", ttl=self._auto_ttl())
                if ok:
                    action = "blocked"
                    reason += " (auto-block)"

        self.store.insert_alert(
            {
                "ts": time.time(),
                "src_ip": initiator,
                "dst_ip": row["dst_ip"],
                "dst_port": row["dst_port"],
                "proto": row["proto"],
                "score": prediction.score,
                "verdict": prediction.label,
                "action": action,
                "reason": reason,
            }
        )
        log.info(
            "ATTACK %s:%s -> %s:%s (%s) score=%.3f action=%s",
            row["src_ip"],
            row["src_port"],
            row["dst_ip"],
            row["dst_port"],
            row["service"],
            prediction.score,
            action,
        )

    def _should_auto_block(self, ip: str) -> bool:
        window = float(self.cfg.get("firewall.auto_block_window_s", 60))
        threshold = int(self.cfg.get("firewall.auto_block_threshold", 5))
        if self.store.block_exists(ip):
            return False
        now = time.time()
        history = self._attack_history[ip]
        history.append(now)
        while history and now - history[0] > window:
            history.popleft()
        return len(history) >= threshold

    def _auto_ttl(self) -> int:
        return int(float(self.cfg.get("firewall.auto_block_ttl_s", 600)))

    def _maintenance_loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._expire_blocks()
                self._ensure_table_alive()
            except Exception:
                log.exception("maintenance error")
            self._stop.wait(10)

    def _ensure_table_alive(self) -> None:
        if not self.runtime_blocking or self.mode == "monitor" or not self.firewall.available():
            return
        if not self.firewall.table_exists():
            log.warning("nftables table missing, recreating and restoring blocks")
            if self.firewall.ensure_table():
                self.firewall.restore(self.store.list_blocks())

    def _expire_blocks(self) -> None:
        for entry in self.store.expired_blocks():
            self.firewall.unblock(entry["ip"])
            self.store.remove_block(entry["ip"])
            log.info("auto-block expired for %s", entry["ip"])

    # -- control API (used by the web dashboard) -----------------------------
    def block_ip(self, ip: str, source: str = "manual", ttl: int | None = None) -> tuple[bool, str]:
        if not self.runtime_blocking:
            if self.predictor.backend == "mock":
                return False, "firewall inactive: a real model backend is required"
            return False, "firewall inactive (offline replay or nftables unavailable)"
        if self.mode == "monitor":
            return False, "firewall is in monitor mode"
        return self._block(ip, source=source, ttl=ttl)

    def kernel_blocks(self) -> list[dict]:
        if not self.runtime_blocking:
            return []
        return self.firewall.list_blocked()

    def kernel_counters(self) -> list[dict]:
        if not self.runtime_blocking:
            return []
        return self.firewall.counters()

    def _block(self, ip: str, source: str, ttl: int | None) -> tuple[bool, str]:
        with self._block_lock:
            ok, message = self.firewall.block(ip, ttl_s=ttl)
            if ok:
                expires = time.time() + ttl if ttl else None
                self.store.add_block(ip, source=source, expires_ts=expires, note=message)
            return ok, message

    def unblock_ip(self, ip: str) -> tuple[bool, str]:
        with self._block_lock:
            ok, message = self.firewall.unblock(ip)
            self.store.remove_block(ip)
            return ok, message

    def set_mode(self, mode: str) -> str:
        mode = (mode or "").lower()
        if mode not in {"monitor", "manual", "auto"}:
            raise ValueError("mode must be one of: monitor, manual, auto")
        self.mode = mode
        self.store.set_setting("firewall_mode", mode)
        if mode != "monitor" and self.firewall.available() and not self.firewall.table_exists():
            if self.firewall.ensure_table():
                self.firewall.restore(self.store.list_blocks())
        log.info("firewall mode set to %s", mode)
        return mode

    # -- reporting -----------------------------------------------------------
    def interface_report(self) -> dict:
        from .netinfo import default_route, detect_advertise_ip, ipv4_addresses

        advertise = detect_advertise_ip(self.cfg.get("web.advertise_ip", "auto"))
        return {
            "capture_interface": getattr(self, "interface", self.cfg.get("capture.interface")),
            "default_route": default_route(),
            "addresses": ipv4_addresses(),
            "advertise_ip": advertise,
            "port": int(self.cfg.get("web.port", 80)),
        }

    def summary(self) -> dict:
        return {
            "source": self.source,
            "interface": self.interface_report(),
            "stats": self.stats.snapshot(
                active_flows=self.flowmeter.active_flow_count(),
                mode=self.mode,
                backend=self.predictor.backend,
            ),
            "model": self.predictor.model_info(),
            "firewall": {
                "mode": self.mode,
                "available": self.runtime_blocking,
                "table": self.firewall.table,
                "blocked": self.store.list_blocks(),
                "allowlist": [str(net) for net in self.firewall.allowlist],
                "threshold": int(self.cfg.get("firewall.auto_block_threshold", 5)),
                "ttl_s": self._auto_ttl(),
            },
            "flows": self.store.flow_totals(),
            "alerts": self.store.alert_counts(),
        }
