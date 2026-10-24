"""Flask web application: REST API + dashboard for the IDS firewall."""

from __future__ import annotations

import logging
import re
import subprocess

from flask import Flask, jsonify, render_template, request

from . import __version__
from .service import IdsService

log = logging.getLogger("idsfw.webapp")


# ---------------------------------------------------------------------------
# Connected-client helpers
# ---------------------------------------------------------------------------

_LEASES_PATHS = [
    "/var/lib/misc/dnsmasq.leases",
    "/tmp/dhcp.leases",
    "/var/lib/dhcpcd5/dhcpcd-ap0.lease",
]


def _read_leases() -> dict[str, dict]:
    """Parse dnsmasq lease file → {ip: {mac, hostname}}."""
    leases: dict[str, dict] = {}
    for path in _LEASES_PATHS:
        try:
            with open(path) as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 4:
                        mac = parts[1].lower()
                        ip = parts[2]
                        hostname = parts[3] if parts[3] != "*" else ""
                        leases[ip] = {"mac": mac, "hostname": hostname}
            break
        except (OSError, IOError):
            continue
    return leases


def _read_arp(ap_iface: str = "ap0") -> dict[str, dict]:
    """Parse /proc/net/arp for clients on the AP interface → {ip: {mac}}."""
    clients: dict[str, dict] = {}
    try:
        with open("/proc/net/arp") as fh:
            for line in fh:
                parts = line.split()
                if len(parts) < 6:
                    continue
                ip, _, flags, mac, _, iface = parts[:6]
                if ip == "IP":  # header
                    continue
                if flags == "0x0":  # incomplete entry
                    continue
                if iface == ap_iface:
                    clients[ip] = {"mac": mac.lower()}
    except OSError:
        pass
    return clients


def get_connected_clients(ap_iface: str = "ap0") -> list[dict]:
    """Merge ARP table + DHCP leases → list of connected client dicts."""
    arp = _read_arp(ap_iface)
    leases = _read_leases()
    result = []
    for ip, info in arp.items():
        lease = leases.get(ip, {})
        result.append(
            {
                "ip": ip,
                "mac": info["mac"],
                "hostname": lease.get("hostname", ""),
                "source": "arp+dhcp" if ip in leases else "arp",
            }
        )
    # also include any leases not yet in ARP cache (recently connected)
    for ip, lease in leases.items():
        if ip not in arp:
            result.append(
                {
                    "ip": ip,
                    "mac": lease["mac"],
                    "hostname": lease.get("hostname", ""),
                    "source": "dhcp",
                }
            )
    return sorted(result, key=lambda x: x["ip"])


def create_app(service: IdsService) -> Flask:
    app = Flask(__name__)
    app.config["SERVICE"] = service

    def svc() -> IdsService:
        return app.config["SERVICE"]

    # -- pages ---------------------------------------------------------------
    @app.get("/")
    def dashboard():
        cfg = svc().cfg
        return render_template(
            "dashboard.html",
            version=__version__,
            refresh_ms=int(cfg.get("web.refresh_ms", 2000)),
            port=int(cfg.get("web.port", 80)),
        )

    # -- API -----------------------------------------------------------------
    @app.get("/api/health")
    def health():
        return jsonify({"status": "ok", "version": __version__})

    @app.get("/api/summary")
    def summary():
        return jsonify(svc().summary())

    @app.get("/api/timeseries")
    def timeseries():
        points = min(int(request.args.get("points", 120)), 600)
        return jsonify(svc().stats.timeseries(points))

    @app.get("/api/flows")
    def flows():
        limit = min(int(request.args.get("limit", 50)), 500)
        verdict = request.args.get("verdict")
        return jsonify({"flows": svc().store.recent_flows(limit, verdict)})

    @app.get("/api/alerts")
    def alerts():
        limit = min(int(request.args.get("limit", 50)), 500)
        return jsonify({"alerts": svc().store.recent_alerts(limit)})

    @app.get("/api/analytics")
    def analytics():
        store = svc().store
        window = int(request.args.get("window", 300))
        return jsonify(
            {
                "window_s": window,
                "top_talkers": store.top_talkers(window),
                "top_attackers": store.top_attackers(window),
                "protocols": store.protocol_breakdown(window),
                "destination_ports": store.destination_ports(window),
            }
        )

    @app.get("/api/blocks")
    def list_blocks():
        blocks = svc().store.list_blocks()
        return jsonify(
            {
                "blocks": blocks,
                "kernel": svc().kernel_blocks(),
                "counters": svc().kernel_counters(),
                "mode": svc().mode,
                "available": svc().runtime_blocking,
            }
        )

    @app.post("/api/blocks")
    def add_block():
        payload = request.get_json(silent=True) or {}
        ip = (payload.get("ip") or "").strip()
        if not ip:
            return jsonify({"ok": False, "error": "ip is required"}), 400
        ttl = payload.get("ttl")
        try:
            ttl = int(ttl) if ttl else None
        except (TypeError, ValueError):
            return jsonify({"ok": False, "error": "ttl must be an integer"}), 400
        ok, message = svc().block_ip(ip, source="manual", ttl=ttl)
        return jsonify({"ok": ok, "message": message}), (200 if ok else 400)

    @app.delete("/api/blocks/<path:ip>")
    def remove_block(ip: str):
        ok, message = svc().unblock_ip(ip)
        return jsonify({"ok": ok, "message": message}), (200 if ok else 400)

    @app.post("/api/mode")
    def set_mode():
        payload = request.get_json(silent=True) or {}
        try:
            mode = svc().set_mode(payload.get("mode", ""))
        except ValueError as exc:
            return jsonify({"ok": False, "error": str(exc)}), 400
        return jsonify({"ok": True, "mode": mode})

    @app.get("/api/netinfo")
    def netinfo():
        return jsonify(svc().interface_report())

    @app.get("/api/clients")
    def connected_clients():
        """Returns devices currently connected to the Pi's hotspot (ap0)."""
        # Detect which interface is the AP (has 192.168.50.x address)
        from .netinfo import ipv4_addresses
        ap_iface = "ap0"  # default
        for a in ipv4_addresses():
            if a["ip"].startswith("192.168.50."):
                ap_iface = a["iface"]
                break
        clients = get_connected_clients(ap_iface)
        return jsonify({"ap_interface": ap_iface, "clients": clients, "count": len(clients)})

    @app.get("/api/model")
    def model_info():
        return jsonify(svc().predictor.model_info())

    return app


def run_server(service: IdsService, host: str | None = None, port: int | None = None) -> None:
    cfg = service.cfg
    host = host or cfg.get("web.host", "0.0.0.0")
    port = int(port or cfg.get("web.port", 80))
    app = create_app(service)
    app.run(host=host, port=port, threaded=True, debug=False, use_reloader=False)
