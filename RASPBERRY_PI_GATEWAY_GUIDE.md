# Raspberry Pi Gateway and WLAN Protection Guide

This guide explains how to place the AI firewall in the traffic path of a
WLAN while allowing an independent Pi-hole installation to remain available
on the same Raspberry Pi.

Pi-hole is a separate project. Nothing in this guide changes Pi-hole's
source code, configuration, database, DNS service, DHCP service, or web
server. It is mentioned only because both applications may use the same
Raspberry Pi.

The firewall can analyse traffic captured from an interface without being a
gateway. However, it can only block traffic that actually crosses the Pi.
Changing `--iface` alone does not make the Pi a router.

## 1. Choose the network topology

The recommended topology has separate WAN and LAN sides:

```text
Upstream router / Internet
          |
       WAN side
    Raspberry Pi 5
       LAN side
          |
   Switch or Wi-Fi AP
          |
       WLAN clients
```

Example interface assignments:

```text
eth0  = LAN-side interface for protected clients
wlan0 = WAN-side connection to the existing router
```

The reverse arrangement is also valid. Confirm the actual names with:

```bash
ip -br link
ip -4 addr
ip -4 route
```

The interface shown in the default route is normally the upstream/WAN
interface. The protected clients must use the Pi's LAN address as their
default gateway.

## 2. Independent Pi-hole installation

Pi-hole commonly uses:

- TCP/UDP port 53 for DNS
- TCP port 80 for its web interface
- DHCP, if enabled

The firewall dashboard should use another port, such as `8080`:

```yaml
web:
  host: 0.0.0.0
  port: 8080
```

Do not stop, reconfigure, or move Pi-hole. Open this project's firewall
dashboard at:

```text
http://<pi-lan-ip>:8080/
```

Any DHCP or routing changes belong to the network/Pi-hole deployment, not to
this firewall project. This project only captures the configured interface
and serves its own dashboard.

## 3. Confirm the current network before changing it

Run these commands and save the output:

```bash
ip -br addr
ip -4 route
sudo ss -ltnup
```

Record:

- the WAN interface
- the LAN interface
- the Pi address on each interface
- the current default gateway
- the Pi-hole services and ports

Do not continue until you know which interface is WAN and which is LAN.

## 4. Configure the firewall dashboard

Edit `config.yaml`:

```yaml
capture:
  # Capture the LAN-side traffic that should be analysed.
  interface: eth0

web:
  host: 0.0.0.0
  # Pi-hole normally owns port 80.
  port: 8080
```

Replace `eth0` with the actual LAN-side interface. On some Raspberry Pi OS
installations the wired interface is named `end0`.

Start in monitor mode:

```bash
sudo ./venv/bin/python run.py \
  --config ./config.yaml \
  --iface eth0 \
  --mode monitor \
  --port 8080
```

Check the dashboard and API:

```bash
curl http://<pi-lan-ip>:8080/api/health
curl http://<pi-lan-ip>:8080/api/netinfo
curl http://<pi-lan-ip>:8080/api/model
```

The model backend must be `tf` or `tflite`. Do not use live blocking when the
API reports `mock`.

## 5. Enable forwarding

For a temporary test:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

For persistence:

```bash
sudo tee /etc/sysctl.d/99-idsfw-gateway.conf >/dev/null <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
EOF
sudo sysctl --system
```

Confirm:

```bash
sysctl net.ipv4.ip_forward
```

Expected output:

```text
net.ipv4.ip_forward = 1
```

## 6. Configure routing and NAT

If the LAN uses private addresses and the upstream router does not have a
route back to the LAN subnet, NAT is required. The installer can create a
masquerade rule for the detected default-route interface:

```bash
sudo ./setup.sh --iface eth0 --mode monitor --nat
```

Only use `--nat` after verifying the default route points to the WAN
interface. The command must be run as root and may update nftables
configuration.

If the upstream router has a static route to the protected LAN subnet, NAT may
not be needed. Routing and DHCP design are network-specific; verify the
result with the network administrator before applying it to a live WLAN.

## 7. Move clients behind the Pi

The test client must receive or be configured with:

- an IP address on the Pi's LAN subnet
- the Pi's LAN address as its default gateway
- Pi-hole or another DNS resolver as its DNS server

Verify from a client:

```bash
ip route
nslookup example.com
```

The default route must point to the Raspberry Pi. If it still points to the
old router, the firewall is not protecting that client.

On the Pi, confirm packets are visible:

```bash
sudo tcpdump -ni eth0 'ip and (tcp or udp)'
```

Then browse from the test client and confirm that the dashboard counters and
flow list update.

## 8. Test blocking safely

Use monitor mode first. After confirming real traffic and the model backend,
restart in manual mode:

```bash
sudo ./venv/bin/python run.py \
  --config ./config.yaml \
  --iface eth0 \
  --mode manual \
  --port 8080
```

Use the dashboard to block only a disposable test address. Check the current
state:

```bash
curl http://<pi-lan-ip>:8080/api/blocks
sudo nft list table inet idsfw
```

Do not block the Pi's own management address, the LAN gateway address, or the
upstream router. Do not change Pi-hole configuration as part of this test.

Automatic blocking should be enabled only after false positives have been
reviewed:

```bash
sudo ./venv/bin/python run.py \
  --config ./config.yaml \
  --iface eth0 \
  --mode auto \
  --port 8080
```

## 9. Rollback

If clients lose connectivity:

1. Stop the firewall:

   ```bash
   sudo systemctl stop idsfw
   ```

2. Remove temporary forwarding if it was only for the test:

   ```bash
   sudo sysctl -w net.ipv4.ip_forward=0
   ```

3. Restore the previous DHCP default gateway.
4. Remove only firewall rules created for this project after inspecting them:

   ```bash
   sudo nft list table inet idsfw
   ```

Do not flush all nftables rules on a Pi that is also running Pi-hole or other
services. Inspect and remove only the `idsfw` table and rules created by this
project. Do not remove rules belonging to Pi-hole or another application.

## 10. systemd operation

After the manual test is successful, configure the service:

```bash
sudo systemctl enable --now idsfw
sudo systemctl status idsfw
journalctl -u idsfw -f
```

The service uses this project's `config.yaml`, so keep the LAN capture
interface and dashboard port there. If another independent application uses
port 80, use an unused firewall port such as `8080`.

## Final checklist

- [ ] WAN and LAN interfaces identified
- [ ] Protected clients physically/logically behind the Pi
- [ ] Clients use the Pi as their default gateway
- [ ] Independent services remain untouched
- [ ] This firewall dashboard uses an unused port such as 8080
- [ ] IPv4 forwarding enabled
- [ ] NAT or upstream routing configured
- [ ] Real TensorFlow/TFLite backend confirmed
- [ ] Monitor mode tested with real client traffic
- [ ] Manual blocking tested safely
- [ ] Automatic mode enabled only after reviewing detections
