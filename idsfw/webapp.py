"""Flask web application: REST API + dashboard for the IDS firewall."""

from __future__ import annotations

import logging

from flask import Flask, jsonify, render_template, request

from . import __version__
from .service import IdsService

log = logging.getLogger("idsfw.webapp")


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
