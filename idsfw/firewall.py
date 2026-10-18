"""nftables blocklist management.

Blocked addresses are kept in two nftables sets inside a dedicated ``inet``
table.  Rules match traffic **forwarded through the Pi** (the gateway case),
so the Pi never locks itself (or the dashboard) out.

Blocking is only effective when the Pi is in the forwarding path of the
traffic it monitors - i.e. when it acts as the LAN gateway/router.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import shutil
import subprocess
from typing import Iterable, Optional

log = logging.getLogger("idsfw.firewall")


class FirewallError(RuntimeError):
    pass


class Firewall:
    def __init__(self, table: str = "idsfw", allowlist: Iterable[str] | None = None) -> None:
        self.table = table
        self.allowlist = [ipaddress.ip_network(item, strict=False) for item in (allowlist or [])]
        self.last_error: Optional[str] = None

    # -- helpers -------------------------------------------------------------
    @staticmethod
    def available() -> bool:
        return shutil.which("nft") is not None

    def _run(self, args: list[str], stdin: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            args, input=stdin, capture_output=True, text=True, timeout=10, check=False
        )

    def is_allowlisted(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return True  # malformed -> never block
        return any(address in network for network in self.allowlist)

    # -- table setup ---------------------------------------------------------
    def ensure_table(self) -> bool:
        """Creates (or resets) the idsfw table, sets and forward rules."""
        if not self.available():
            self.last_error = "nft binary not found"
            log.error("nftables not available (%s)", self.last_error)
            return False
        script = f"""
table inet {self.table} {{
    set blocked4 {{
        type ipv4_addr
        flags timeout
    }}
    set blocked6 {{
        type ipv6_addr
        flags timeout
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        ip saddr @blocked4 counter drop
        ip daddr @blocked4 counter drop
        ip6 saddr @blocked6 counter drop
        ip6 daddr @blocked6 counter drop
    }}
}}
"""
        result = self._run(["nft", "-f", "-"], stdin=script)
        if result.returncode != 0:
            self.last_error = result.stderr.strip()
            log.error("failed to create nftables table: %s", self.last_error)
            return False
        self.last_error = None
        log.info("nftables table inet %s ready", self.table)
        return True

    def table_exists(self) -> bool:
        if not self.available():
            return False
        return self._run(["nft", "list", "table", "inet", self.table]).returncode == 0

    # -- block / unblock -----------------------------------------------------
    def _set_name(self, ip: str) -> str:
        return "blocked6" if ":" in ip else "blocked4"

    def block(self, ip: str, ttl_s: int | None = None) -> tuple[bool, str]:
        if self.is_allowlisted(ip):
            return False, f"{ip} is allowlisted"
        if not self.available():
            return False, "nftables not available"
        element = f"{ip} timeout {int(ttl_s)}s" if ttl_s else ip
        result = self._run(
            ["nft", "add", "element", "inet", self.table, self._set_name(ip), f"{{ {element} }}"]
        )
        if result.returncode != 0:
            message = result.stderr.strip() or "nft add element failed"
            log.warning("block %s failed: %s", ip, message)
            return False, message
        log.info("blocked %s%s", ip, f" for {ttl_s}s" if ttl_s else "")
        return True, "blocked"

    def unblock(self, ip: str) -> tuple[bool, str]:
        if not self.available():
            return False, "nftables not available"
        result = self._run(
            ["nft", "delete", "element", "inet", self.table, self._set_name(ip), f"{{ {ip} }}"]
        )
        if result.returncode != 0:
            message = result.stderr.strip()
            if "No such file or directory" in message or "not found" in message.lower():
                return True, "not blocked"
            log.warning("unblock %s failed: %s", ip, message)
            return False, message
        log.info("unblocked %s", ip)
        return True, "unblocked"

    def list_blocked(self) -> list[dict]:
        """Reads the current nftables sets (source of truth for the kernel)."""
        if not self.available():
            return []
        entries: list[dict] = []
        for set_name in ("blocked4", "blocked6"):
            result = self._run(["nft", "-j", "list", "set", "inet", self.table, set_name])
            if result.returncode != 0:
                continue
            try:
                payload = json.loads(result.stdout)
            except json.JSONDecodeError:
                continue
            for item in payload.get("nftables", []):
                element = item.get("element")
                if not element:
                    continue
                entries.append(
                    {
                        "ip": element.get("elem", {}).get("val")
                        if isinstance(element.get("elem"), dict)
                        else element.get("elem"),
                        "expires_ms": element.get("expires"),
                        "set": set_name,
                    }
                )
        return entries

    def counters(self) -> list[dict]:
        """Per-rule drop counters (useful to prove blocking is active)."""
        if not self.available():
            return []
        result = self._run(["nft", "-j", "list", "chain", "inet", self.table, "forward"])
        if result.returncode != 0:
            return []
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        out = []
        for item in payload.get("nftables", []):
            rule = item.get("rule")
            if not rule:
                continue
            expr = rule.get("expr", [])
            comment = " ".join(str(e.get("match", {})) for e in expr if "match" in e)
            packet_count = None
            byte_count = None
            for e in expr:
                if "counter" in e:
                    packet_count = e["counter"].get("packets")
                    byte_count = e["counter"].get("bytes")
            out.append({"rule": comment, "packets": packet_count, "bytes": byte_count})
        return out

    def restore(self, blocks: Iterable[dict]) -> int:
        """Re-applies persisted blocks after a restart/reboot."""
        restored = 0
        for entry in blocks:
            ttl = None
            expires_ts = entry.get("expires_ts")
            if expires_ts:
                import time

                remaining = int(expires_ts - time.time())
                if remaining <= 0:
                    continue
                ttl = remaining
            ok, _ = self.block(entry["ip"], ttl)
            restored += 1 if ok else 0
        if restored:
            log.info("restored %s nftables blocks", restored)
        return restored
