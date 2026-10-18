"""Network interface / address discovery used for capture and the dashboard URL.

Uses ``ip -j`` (iproute2, always present on Debian) and falls back to plain
socket calls if the JSON output is unavailable.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import socket
import subprocess

log = logging.getLogger("idsfw.netinfo")


def _run(args: list[str]) -> str:
    try:
        return subprocess.run(
            args, capture_output=True, text=True, timeout=5, check=False
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:  # pragma: no cover
        log.debug("command %s failed: %s", args, exc)
        return ""


def default_route() -> dict | None:
    """Returns ``{"dev": ..., "gateway": ...}`` for the IPv4 default route."""
    out = _run(["ip", "-j", "-4", "route", "show", "default"])
    try:
        routes = json.loads(out)
    except json.JSONDecodeError:
        return None
    if not routes:
        return None
    route = routes[0]
    return {"dev": route.get("dev"), "gateway": route.get("gateway")}


def link_states() -> dict[str, str]:
    """Maps interface name -> operstate (``up``/``down``/``unknown``)."""
    out = _run(["ip", "-j", "link", "show"])
    try:
        links = json.loads(out)
    except json.JSONDecodeError:
        return {}
    return {link.get("ifname"): link.get("operstate", "unknown") for link in links if link.get("ifname")}


def ipv4_addresses() -> list[dict]:
    """All non-loopback IPv4 addresses: ``[{iface, ip, prefixlen, private}]``."""
    out = _run(["ip", "-j", "-4", "addr", "show"])
    result: list[dict] = []
    try:
        interfaces = json.loads(out)
    except json.JSONDecodeError:
        interfaces = []
    for iface in interfaces:
        name = iface.get("ifname")
        if not name or name == "lo":
            continue
        for info in iface.get("addr_info", []):
            if info.get("family") != "inet":
                continue
            addr = info.get("local")
            if not addr:
                continue
            try:
                ip = ipaddress.ip_address(addr)
                private = ip.is_private and not ip.is_loopback
            except ValueError:
                private = False
            result.append(
                {"iface": name, "ip": addr, "prefixlen": info.get("prefixlen", 24), "private": private}
            )
    if not result:
        result = _socket_fallback()
    return result


def _socket_fallback() -> list[dict]:  # pragma: no cover - rarely needed
    try:
        host = socket.gethostname()
        addr = socket.gethostbyname(host)
    except OSError:
        return []
    try:
        private = ipaddress.ip_address(addr).is_private
    except ValueError:
        private = False
    return [{"iface": "unknown", "ip": addr, "prefixlen": 24, "private": private}]


def detect_advertise_ip(preferred: str | None = None) -> str | None:
    """Best guess of the IP on which the dashboard is reachable from the LAN.

    On a gateway Pi the default route points at the WAN side, so a private
    address on a *different* interface is the LAN-facing one.
    """
    if preferred and preferred != "auto":
        return preferred

    addresses = [a for a in ipv4_addresses() if a["private"]]
    if not addresses:
        all_addrs = ipv4_addresses()
        return all_addrs[0]["ip"] if all_addrs else None

    wan_iface = (default_route() or {}).get("dev")
    lan_candidates = [a for a in addresses if a["iface"] != wan_iface]
    chosen = (lan_candidates or addresses)[0]
    return chosen["ip"]


def detect_capture_interface(configured: str | None = None) -> str | None:
    """Resolves ``capture.interface`` == ``auto`` to a concrete device name."""
    if configured and configured != "auto":
        return configured

    states = link_states()
    wan_iface = (default_route() or {}).get("dev")
    private = [a for a in ipv4_addresses() if a["private"]]
    lan_candidates = [a["iface"] for a in private if a["iface"] != wan_iface]

    for candidate in lan_candidates:
        if states.get(candidate) == "up":
            return candidate
    if lan_candidates:
        return lan_candidates[0]
    if wan_iface:
        return wan_iface

    for name, state in states.items():
        if name != "lo" and state == "up":
            return name
    return None


def dashboard_urls(ip: str | None, port: int) -> list[str]:
    """Human-readable URLs to print on startup."""
    urls = []
    if ip:
        suffix = "" if port == 80 else f":{port}"
        urls.append(f"http://{ip}{suffix}/")
        hostname = socket.gethostname()
        if hostname:
            base = hostname.split(".")[0]
            urls.append(f"http://{base}.local{suffix}/")
    suffix = "" if port == 80 else f":{port}"
    urls.append(f"http://localhost{suffix}/")
    return urls
