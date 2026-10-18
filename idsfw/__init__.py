"""AI-driven network intrusion detection firewall for Raspberry Pi 5.

Pipeline: live capture -> CICFlowMeter-compatible flow features -> Keras
anomaly/attack classifier -> SQLite store + nftables blocking -> web dashboard.
"""

__version__ = "1.0.0"
__all__ = ["__version__"]
