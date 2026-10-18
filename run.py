#!/usr/bin/env python3
"""Entry point for the AI-driven firewall / network analyser.

Examples
--------
Live capture + dashboard (default, needs root for raw sockets)::

    sudo ./venv/bin/python run.py

Validate the pipeline against a capture file (no root needed for ethtool-free
offline replay, no dashboard unless ``--serve``)::

    ./venv/bin/python run.py --pcap tests/data/sample.pcap

Serve the dashboard on a different port::

    sudo ./venv/bin/python run.py --port 8080
"""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time

from idsfw import __version__
from idsfw.config import load_config
from idsfw.netinfo import dashboard_urls, detect_advertise_ip
from idsfw.service import IdsService

log = logging.getLogger("idsfw")


def configure_logging(cfg, level: str | None = None) -> None:
    resolved = (level or cfg.get("logging.level", "INFO")).upper()
    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]
    log_file = cfg.get("logging.file")
    if log_file:
        handlers.append(logging.FileHandler(log_file))
    logging.basicConfig(
        level=getattr(logging, resolved, logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        handlers=handlers,
        force=True,
    )
    logging.getLogger("werkzeug").setLevel(logging.WARNING)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AI-driven network IDS firewall")
    parser.add_argument("--config", default="config.yaml", help="path to config.yaml")
    parser.add_argument("--pcap", help="replay a capture file instead of sniffing live traffic")
    parser.add_argument("--iface", help="override capture.interface")
    parser.add_argument("--host", help="override web.host")
    parser.add_argument("--port", type=int, help="override web.port")
    parser.add_argument(
        "--mode", choices=["monitor", "manual", "auto"], help="override firewall.mode"
    )
    parser.add_argument("--log-level", help="override logging.level")
    parser.add_argument(
        "--serve", action="store_true", help="also start the dashboard when using --pcap"
    )
    parser.add_argument("--version", action="version", version=f"idsfw {__version__}")
    return parser.parse_args(argv)


def print_banner(service: IdsService) -> None:
    cfg = service.cfg
    port = int(cfg.get("web.port", 80))
    ip = detect_advertise_ip(cfg.get("web.advertise_ip", "auto"))
    info = service.predictor.model_info()

    print("=" * 68)
    print(f" AI-Driven Firewall / Network Analyser  v{__version__}")
    print("=" * 68)
    print(f" source           : {service.source}" + (f" ({service.pcap_path})" if service.pcap_path else ""))
    print(f" capture iface    : {service.interface}")
    print(f" model backend    : {info['backend']}  ({info['features']} features, threshold {info['threshold']})")
    print(f" firewall mode    : {service.mode} (nftables {'available' if service.runtime_blocking else 'inactive'})")
    if info["backend"] == "mock":
        print(" !! MOCK MODEL ACTIVE - install tensorflow for real detections !!")
    print("-" * 68)
    for url in dashboard_urls(ip, port):
        print(f" dashboard        : {url}")
    print("=" * 68, flush=True)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cfg = load_config(args.config)

    if args.iface:
        cfg.set("capture.interface", args.iface)
    if args.host:
        cfg.set("web.host", args.host)
    if args.port:
        cfg.set("web.port", args.port)
    if args.mode:
        cfg.set("firewall.mode", args.mode)
        cfg.set("firewall.mode_override", args.mode)

    configure_logging(cfg, args.log_level)

    service = IdsService(cfg)
    if args.mode:
        service.set_mode(args.mode)

    try:
        service.start(pcap=args.pcap)
    except Exception as exc:
        log.error("failed to start: %s", exc)
        return 2

    print_banner(service)

    stop_requested = {"value": False}

    def _handle_signal(signum, _frame):
        if stop_requested["value"]:
            return
        stop_requested["value"] = True
        log.info("received signal %s, shutting down", signum)
        service.stop()

    signal.signal(signal.SIGINT, _handle_signal)
    signal.signal(signal.SIGTERM, _handle_signal)

    if args.pcap and not args.serve:
        while not service.replay_done and not stop_requested["value"]:
            time.sleep(0.2)
        time.sleep(0.5)
        snapshot = service.stats.snapshot(active_flows=service.flowmeter.active_flow_count())
        print("-" * 68)
        print(f" packets         : {snapshot['packets_total']}")
        print(f" flows scored    : {service.predictor.rows_scored}")
        print(f" attacks detected: {service.predictor.attacks}")
        print(f" verdicts        : {snapshot['verdicts']}")
        print(f" dropped packets : {snapshot['dropped_packets']}")
        print("-" * 68, flush=True)
        service.stop()
        return 0

    from idsfw.webapp import run_server

    try:
        run_server(service, host=args.host, port=args.port)
    except KeyboardInterrupt:  # pragma: no cover - interactive use
        pass
    finally:
        service.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
