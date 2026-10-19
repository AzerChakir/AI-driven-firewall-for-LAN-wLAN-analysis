# AI-Driven Firewall for Raspberry Pi 5

This project captures IPv4 TCP/UDP traffic, builds CICFlowMeter-compatible
flows, scores them with the trained model in `model_save/`, stores results in
SQLite, and serves a network dashboard. In `auto` mode, repeated detections
can be blocked with nftables.

For the complete gateway setup, interface layout, Pi-hole coexistence,
forwarding/NAT, client routing, testing, and rollback procedure, see
[RASPBERRY_PI_GATEWAY_GUIDE.md](./RASPBERRY_PI_GATEWAY_GUIDE.md).

> **Separate project:** Pi-hole is not part of this project. This firewall
> does not modify Pi-hole's source code, configuration, database, DNS, DHCP,
> or web server. Pi-hole is mentioned only because both applications may run
> on the same Raspberry Pi.

## Requirements

- Raspberry Pi 5 running 64-bit Raspberry Pi OS (Bookworm) or Debian 12
- A LAN interface visible to the Pi (`eth0`, `end0`, or `wlan0`)
- The Pi should be the gateway for traffic that must be blocked. A passive
  capture can detect traffic but cannot block packets elsewhere on the network.
- The trained files in `model_save/`: `ids_model.keras`,
  `preprocessing.pkl`, and `metadata.json`

TensorFlow is preferred. If TensorFlow is not available for the Pi image,
convert the model on another TensorFlow machine and copy
`model_save/ids_model.tflite` into this project:

```bash
python tools/convert_tflite.py --quantize
```

The installer refuses to enable the service when only the development mock
backend is available.

## Install on the Pi

Copy the complete project directory, including `model_save/`, to the Pi, then:

```bash
cd Firewall
sudo ./setup.sh --iface eth0 --mode manual
```

Use `--iface end0` for the Pi's wired interface when that is its actual name.
Use `--mode monitor` first to verify detections without changing nftables.
For a gateway with an upstream WAN interface, add `--nat` only when IPv4
forwarding and masquerading are intended:

```bash
sudo ./setup.sh --iface eth0 --mode manual --nat
```

The installer enables IPv4 forwarding, installs the `idsfw.service` systemd
unit, and prints the dashboard URL. The dashboard is bound to all interfaces
and is normally reachable at:

```
http://<pi-lan-ip>/
```

Find the address later with `ip -4 addr` or inspect the service log:

```bash
sudo systemctl status idsfw
journalctl -u idsfw -f
```

Open the configured dashboard port on the Pi/LAN firewall if another firewall
is enabled. If another independent application already uses port 80, change
`web.port` in `config.yaml` to an unused port such as `8080`. This project
does not change the other application's configuration.

## Configuration and operation

Important settings are in `config.yaml`:

- `capture.interface`: interface to analyse, or `auto`
- `firewall.mode`: `monitor`, `manual`, or `auto`
- `web.host` and `web.port`: dashboard bind address and port
- `firewall.allowlist`: networks that must never be blocked

The API and dashboard expose current flows, alerts, model status, interface
addresses, and blocklist state. Useful checks after boot:

```bash
curl http://<pi-lan-ip>/api/health
curl http://<pi-lan-ip>/api/netinfo
curl http://<pi-lan-ip>/api/model
```

Offline validation does not require root:

```bash
./venv/bin/python run.py --pcap path/to/capture.pcap
```

The project deliberately does not use the mock backend for live firewall
blocking. If `/api/model` reports `"backend": "mock"`, install a supported
TensorFlow/TFLite runtime and restart the service.

## Service maintenance

```bash
sudo systemctl restart idsfw
sudo systemctl disable --now idsfw
sudo systemctl enable --now idsfw
```

The SQLite database is stored under the project directory at `data/idsfw.db`.
Relative paths in `config.yaml` are resolved relative to that file, so the
service is safe to start independently of the current shell directory.
