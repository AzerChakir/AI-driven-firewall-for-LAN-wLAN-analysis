"""Configuration loading (``config.yaml``) with sane defaults."""

from __future__ import annotations

import copy
import logging
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger("idsfw.config")

DEFAULTS: dict[str, Any] = {
    "capture": {
        "interface": "auto",
        "bpf_filter": "ip and (tcp or udp)",
        "snaplen": 256,
        "queue_size": 200000,
        "promiscuous": True,
    },
    "model": {
        "dir": "model_save",
        "threshold": None,
        "batch_size": 64,
        "batch_interval_s": 1.0,
    },
    "flows": {"timeout_s": 120, "idle_timeout_s": 120},
    "firewall": {
        "mode": "manual",
        "auto_block_threshold": 5,
        "auto_block_window_s": 60,
        "auto_block_ttl_s": 600,
        "nft_table": "idsfw",
        "allowlist": ["224.0.0.0/4", "127.0.0.0/8"],
    },
    "web": {
        "host": "0.0.0.0",
        "port": 80,
        "advertise_ip": "auto",
        "refresh_ms": 2000,
    },
    "store": {"path": "data/idsfw.db", "max_flows": 5000, "max_alerts": 2000},
    "logging": {"level": "INFO", "file": None},
}


def _deep_merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


class Config:
    """Nested configuration with attribute and dotted access.

    ``cfg.capture.interface`` and ``cfg.get("capture.interface")`` both work.
    """

    def __init__(self, data: dict[str, Any], path: Path | None = None) -> None:
        object.__setattr__(self, "_data", data)
        object.__setattr__(self, "path", path)

    # -- access --------------------------------------------------------------
    def __getattr__(self, name: str) -> Any:
        data = object.__getattribute__(self, "_data")
        if name in data:
            value = data[name]
            return Config(value) if isinstance(value, dict) else value
        raise AttributeError(name)

    def __contains__(self, name: str) -> bool:
        return name in object.__getattribute__(self, "_data")

    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = object.__getattribute__(self, "_data")
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def set(self, dotted: str, value: Any) -> None:
        node = object.__getattribute__(self, "_data")
        parts = dotted.split(".")
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = value

    def as_dict(self) -> dict[str, Any]:
        return copy.deepcopy(object.__getattribute__(self, "_data"))

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"Config({self.as_dict()!r})"


def load_config(path: str | Path | None = None) -> Config:
    """Loads ``config.yaml`` merged over :data:`DEFAULTS`."""
    config_path = Path(path).expanduser() if path else Path("config.yaml")
    config_path = config_path.resolve()
    data: dict[str, Any] = {}
    if config_path.exists():
        loaded = yaml.safe_load(config_path.read_text()) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"{config_path} must contain a YAML mapping")
        data = loaded
    else:
        log.warning("config file %s not found, using defaults", config_path)
    merged = _deep_merge(DEFAULTS, data)
    # Configuration paths are relative to config.yaml, not to the process
    # working directory. This keeps systemd, shell, and container launches
    # consistent.
    for key in ("model.dir", "store.path", "logging.file"):
        value = merged.get(key.split(".")[0], {}).get(key.split(".")[1])
        if value:
            candidate = Path(str(value)).expanduser()
            if not candidate.is_absolute():
                merged[key.split(".")[0]][key.split(".")[1]] = str(
                    (config_path.parent / candidate).resolve()
                )
    return Config(merged, config_path)
