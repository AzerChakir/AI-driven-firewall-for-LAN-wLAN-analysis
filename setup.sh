#!/usr/bin/env bash
# ---------------------------------------------------------------------------
# AI-driven IDS firewall - Raspberry Pi / Debian 12 installer.
#
#   sudo ./setup.sh [options]
#
# Options:
#   --port N              dashboard HTTP port (default: keep config value, 80)
#   --iface IFACE         capture interface (default: auto-detect LAN)
#   --mode MODE           firewall mode: monitor | manual | auto
#   --nat                 configure nftables masquerade so the Pi routes to WAN
#   --no-tensorflow       install core deps only (requires a TFLite model)
#   --no-service          install dependencies only, do not touch systemd/sysctl
#   --no-apt              skip apt-get (dependencies already installed)
#
# What it does:
#   1. installs OS packages (libpcap, nftables, python venv)
#   2. creates ./venv and installs requirements (optionally + TensorFlow)
#   3. enables IPv4 forwarding (gateway mode)
#   4. optionally adds nftables masquerade on the WAN interface
#   5. installs + starts the idsfw systemd service
# ---------------------------------------------------------------------------
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$APP_DIR/venv"
CONFIG_FILE="$APP_DIR/config.yaml"
SERVICE_FILE="/etc/systemd/system/idsfw.service"
PORT=""
IFACE=""
MODE=""
DO_NAT=0
INSTALL_TENSORFLOW=1
DO_SERVICE=1
DO_APT=1

log()  { printf '\033[1;36m[idsfw]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[idsfw] WARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[idsfw] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port) PORT="${2:?}"; shift 2 ;;
    --iface) IFACE="${2:?}"; shift 2 ;;
    --mode) MODE="${2:?}"; shift 2 ;;
    --nat) DO_NAT=1; shift ;;
    --no-tensorflow) INSTALL_TENSORFLOW=0; shift ;;
    --no-service) DO_SERVICE=0; shift ;;
    --no-apt) DO_APT=0; shift ;;
    -h|--help) sed -n '2,26p' "$0"; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ "$(id -u)" -eq 0 ]] || die "run as root (sudo ./setup.sh)"
[[ -f "$CONFIG_FILE" ]] || die "config.yaml not found next to setup.sh"

# --- 1. OS packages --------------------------------------------------------
if [[ "$DO_APT" -eq 1 ]]; then
  log "installing OS packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y --no-install-recommends \
    python3 python3-venv python3-pip tcpdump nftables iproute2 ca-certificates
  # libpcap name differs between Debian releases; tcpdump already pulls it in
  apt-get install -y --no-install-recommends libpcap0.8 || \
    apt-get install -y --no-install-recommends libpcap0.8t64 || \
    warn "could not install libpcap explicitly (tcpdump should provide it)"
else
  log "skipping apt-get (--no-apt)"
fi

# --- 2. Python virtualenv --------------------------------------------------
log "creating virtualenv at $VENV_DIR"
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip wheel >/dev/null

log "installing core requirements"
"$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt"

if [[ "$INSTALL_TENSORFLOW" -eq 1 ]]; then
  log "installing TensorFlow (this can take several minutes on a Pi)"
  if ! "$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements-tensorflow.txt"; then
    warn "TensorFlow install failed - the service must use a TFLite model"
    warn "you can retry later with: $VENV_DIR/bin/pip install tensorflow"
  fi
fi

# Never install a live firewall that would silently use the development mock.
log "checking that a real model backend is available"
if ! PYTHONPATH="$APP_DIR" "$VENV_DIR/bin/python" - "$APP_DIR/config.yaml" <<'PY'
import sys
from idsfw.config import load_config
from idsfw.inference import Predictor

cfg = load_config(sys.argv[1])
predictor = Predictor(cfg.get("model.dir", "model_save"))
if predictor.backend == "mock":
    raise SystemExit(
        "no TensorFlow/TFLite backend is available; install TensorFlow or "
        "copy model_save/ids_model.tflite before installing the service"
    )
print(f"model backend: {predictor.backend}")
PY
then
  die "a real model backend is required; refusing to install a mock-only firewall"
fi

# --- 3. apply CLI overrides to config.yaml ---------------------------------
if [[ -n "$PORT" || -n "$IFACE" || -n "$MODE" ]]; then
  log "updating config.yaml (port=${PORT:-keep} iface=${IFACE:-keep} mode=${MODE:-keep})"
  "$VENV_DIR/bin/python" - "$CONFIG_FILE" "$PORT" "$IFACE" "$MODE" <<'PY'
import sys, yaml
path, port, iface, mode = sys.argv[1:5]
with open(path) as fh:
    cfg = yaml.safe_load(fh) or {}
if port:
    cfg.setdefault("web", {})["port"] = int(port)
if iface:
    cfg.setdefault("capture", {})["interface"] = iface
if mode:
    cfg.setdefault("firewall", {})["mode"] = mode
with open(path, "w") as fh:
    yaml.safe_dump(cfg, fh, sort_keys=False)
PY
fi

# --- 4. forwarding + optional NAT -----------------------------------------
if [[ "$DO_SERVICE" -eq 1 ]]; then
  log "enabling IPv4 forwarding"
  cat >/etc/sysctl.d/99-idsfw.conf <<'EOF'
# AI-driven firewall: act as a router/gateway
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
EOF
  sysctl -q --system

  if [[ "$DO_NAT" -eq 1 ]]; then
    WAN_IFACE="$(ip -4 route show default | awk '{print $5; exit}')"
    [[ -n "$WAN_IFACE" ]] || die "could not detect the WAN interface for NAT"
    log "configuring masquerade on $WAN_IFACE"
    mkdir -p /etc/nftables.d
    cat >/etc/nftables.d/idsfw-nat.nft <<EOF
table ip idsfw_nat {
    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "$WAN_IFACE" masquerade
    }
}
EOF
    if ! grep -q 'include "/etc/nftables.d/\*.nft"' /etc/nftables.conf 2>/dev/null; then
      echo 'include "/etc/nftables.d/*.nft"' >>/etc/nftables.conf
    fi
    systemctl enable --now nftables
  fi

  # --- 5. systemd unit -----------------------------------------------------
  log "installing systemd service"
  sed "s|__APP_DIR__|$APP_DIR|g" "$APP_DIR/systemd/idsfw.service" >"$SERVICE_FILE"
  systemctl daemon-reload
  systemctl enable idsfw.service
  # make sure the running instance picks up the new code/config
  systemctl restart idsfw.service
  sleep 2
  systemctl --no-pager --lines=15 status idsfw.service || true

  PORT_SHOWN="$(grep -A5 '^web:' "$CONFIG_FILE" | awk '/port:/{print $2; exit}')"
  HOST_IP="$(ip -4 -o addr show scope global | awk '{print $4}' | cut -d/ -f1 | grep -v '^127' | head -n1)"
  echo
  log "installation complete"
  echo "    dashboard: http://${HOST_IP:-<pi-ip>}:${PORT_SHOWN:-80}/"
  echo "    logs:      journalctl -u idsfw -f"
  echo "    restart:   sudo systemctl restart idsfw"
  [[ -n "$HOST_IP" ]] || warn "no global IPv4 address found yet - connect the LAN interface and re-check"
else
  log "installation complete (service not installed, --no-service)"
  echo "    run manually: sudo $VENV_DIR/bin/python $APP_DIR/run.py --config $CONFIG_FILE"
fi
