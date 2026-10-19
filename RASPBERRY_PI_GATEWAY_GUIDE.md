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

The dashboard already polls the live Flask API at the configured
`web.refresh_ms` interval. If it looks static, first verify that real packets
arrive on the selected interface and that the clients actually use the Pi as
their gateway.

## 1. Choose and configure the network topology

The AI firewall can only protect traffic that crosses the Raspberry Pi. The
Pi must therefore be placed **between the upstream network and the WLAN that
you want to protect**. Connecting the Pi to the same switch as the clients is
not enough.

### 1.1 Recommended two-sided gateway layout

Use two independent network sides:

```text
                    WAN side
        +-------------------------------+
        |                               |
Internet / upstream router          wlan0 or eth0
        |                               |
        +--------> Raspberry Pi 5 <-----+
                      |
                      | eth0 or wlan0
                      | LAN side: 192.168.50.1/24
                      |
                switch or Wi-Fi AP
                      |
                 WLAN clients
                 192.168.50.0/24
```

In this example:

| Component | Role | Example |
|---|---|---|
| `wlan0` | WAN/upstream interface | Receives an address from the existing router |
| `eth0` or `end0` | LAN/protected interface | `192.168.50.1/24` |
| Raspberry Pi | Default gateway for protected clients | `192.168.50.1` |
| Test client | Protected WLAN/LAN device | `192.168.50.20/24` |
| Upstream router | Internet gateway for the Pi | For example `192.168.1.1` |

The interface assignment may be reversed:

```text
eth0/end0 = WAN to the existing router
wlan0     = LAN for protected clients
```

What matters is the role, not the interface name:

- **WAN** connects toward the existing router/Internet.
- **LAN** connects toward the clients that the firewall must protect.
- Protected clients use the Pi's **LAN address** as their default gateway.
- The Pi uses the upstream router through its **WAN interface**.

### 1.2 Layouts that do not protect the whole WLAN

This layout does **not** make the Pi a gateway:

```text
Existing router/Wi-Fi ---- WLAN clients
          |
          +---- Raspberry Pi (separate connection)
```

The clients bypass the Pi, so the firewall cannot reliably block their
traffic. It may still capture broadcast or local traffic visible on its
interface, but that is not whole-WLAN protection.

The following can also be valid, but require additional network
configuration outside this project:

- One physical Ethernet connection with separate managed-switch VLANs.
- The Pi operating as a Wi-Fi access point with one interface as WAN and the
  AP bridge as LAN.
- A bridge or routed VLAN deployment designed by a network administrator.

This project does not create a Wi-Fi access point, configure a wireless
bridge, or replace an existing DHCP/DNS application.

### 1.3 Identify the physical interfaces

On the Pi, first disconnect or disable one network side at a time if
necessary, then inspect the interfaces:

```bash
ip -br link
ip -br addr
ip -4 route
```

Typical output may look like:

```text
lo       UNKNOWN        127.0.0.1/8
wlan0    UP             192.168.1.45/24
eth0     UP             192.168.50.1/24
default via 192.168.1.1 dev wlan0
```

This means:

```text
wlan0 = WAN, because the default route uses wlan0
eth0  = LAN, because it has the protected subnet address
```

The default route is normally the WAN side:

```bash
ip -4 route show default
```

The protected/LAN interface must not use the same subnet as the WAN. For
example, do not use `192.168.1.0/24` on both sides. Choose a separate subnet:

```text
WAN: 192.168.1.0/24       existing router network
LAN: 192.168.50.0/24      protected client network
```

### 1.4 Example temporary LAN configuration

For a short test, the following assigns the Pi's LAN address to `eth0`:

```bash
sudo ip link set eth0 up
sudo ip addr add 192.168.50.1/24 dev eth0
ip -4 addr show dev eth0
```

This address is temporary and may disappear after reboot or network service
restart. Do not run the command repeatedly if the address is already
present. Check first:

```bash
ip -4 addr show dev eth0
```

For permanent network configuration, use the network manager already used by
the Raspberry Pi OS image. Configure only one network manager to control an
interface. A persistent LAN address should remain:

```text
LAN interface: eth0
LAN address:   192.168.50.1/24
LAN gateway:   none on the LAN interface
WAN gateway:   existing upstream router, through the WAN interface
```

Do not configure the upstream router as the gateway on the LAN interface.
The Pi itself is the gateway for clients on that side.

### 1.5 Configure a test client

Connect one test client to the Pi's LAN side, then configure or verify:

```text
Client address: 192.168.50.20/24
Client gateway: 192.168.50.1
Client DNS:     existing DNS/Pi-hole address, if desired
```

On a Linux client:

```bash
ip -4 addr
ip -4 route
```

On Windows:

```powershell
ipconfig
route print
```

The client's default route must point to `192.168.50.1`. If it points to the
old router, the client is not behind the AI firewall.

### 1.6 Validate the topology before starting detection

From the Pi:

```bash
ping -c 3 <upstream-router-ip>
ip route get 1.1.1.1
```

From the protected client:

```bash
ping -c 3 192.168.50.1
ping -c 3 1.1.1.1
```

On the Pi, verify traffic arriving from the protected side:

```bash
sudo tcpdump -ni eth0 'ip and (tcp or udp)'
```

Replace `eth0` with the actual LAN interface. If the client can reach the
Pi but cannot reach the Internet, troubleshoot forwarding/NAT in sections 5
and 6. If the client reaches the Internet without packets appearing on the
LAN interface, the client is using another gateway or is physically
connected to the wrong network.

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

## Live gateway procedure

The following is the complete sequence for moving one test client behind the
Pi. Use a test client first; do not migrate the whole WLAN until the test is
successful.

### A. Required topology

The Pi needs two network sides:

```text
Upstream router / Internet
          |
       WAN side
    Raspberry Pi 5
       LAN side
          |
     switch or AP
          |
     test WLAN client
```

For example:

```text
wlan0 = WAN/upstream interface
eth0  = LAN/protected interface
```

The reverse is also valid. A client connected directly to the existing
router bypasses the Pi and cannot be protected by this project. Changing
`--iface` only changes where packets are captured; it does not create a
gateway.

Run these commands on the Pi and identify the actual interface names:

```bash
ip -br link
ip -4 addr
ip -4 route show default
```

The interface shown by the default route is normally WAN. Use the other
interface as LAN. Do not continue until these roles are known.

### B. Keep Pi-hole separate

Pi-hole is an independent project. Do not edit its source, configuration,
database, DNS, DHCP, systemd units, or nftables rules as part of this setup.
The only shared concern is that another service may already use port 80.

Run this firewall dashboard on an unused port:

```yaml
web:
  host: 0.0.0.0
  port: 8080
```

Pi-hole remains on its own ports. The firewall dashboard is:

```text
http://<pi-lan-ip>:8080/
```

### C. Choose a LAN subnet and address

Use a subnet that does not overlap the upstream network. The examples below
use `192.168.50.0/24` and assign the Pi `192.168.50.1` on `eth0`. Replace
these values if your network uses different addresses.

For a temporary test address:

```bash
sudo ip link set eth0 up
sudo ip addr add 192.168.50.1/24 dev eth0
ip -4 addr show dev eth0
```

Make the address persistent using the Raspberry Pi OS network manager already
controlling the interface. Do not configure the same interface simultaneously
with multiple network managers.

The test client must have:

```text
IP address: 192.168.50.x/24
Gateway:    192.168.50.1
DNS:        your existing DNS/Pi-hole address, if desired
```

The gateway setting is essential. If the client still shows the old router as
its default route, its traffic will bypass the Pi.

### D. Enable IPv4 forwarding

Test temporarily:

```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

Persist it:

```bash
sudo tee /etc/sysctl.d/99-idsfw-gateway.conf >/dev/null <<'EOF'
net.ipv4.ip_forward=1
net.ipv4.conf.all.forwarding=1
EOF
sudo sysctl --system
sysctl net.ipv4.ip_forward
```

The expected value is `1`.

### E. Configure NAT

Inspect the WAN route before applying NAT:

```bash
ip -4 route show default
```

If the upstream router has no route back to `192.168.50.0/24`, use the
project installer to enable masquerading on the detected WAN interface:

```bash
sudo ./setup.sh --iface eth0 --mode monitor --nat
```

The `--nat` option does not configure Pi-hole, create an access point, or
change another application's configuration. It enables forwarding and adds
this project's NAT configuration. Verify the result:

```bash
sysctl net.ipv4.ip_forward
sudo nft list ruleset
```

If the upstream router has a static route to the protected LAN, NAT may not
be required.

### F. Configure this project's capture and dashboard

Edit this project's `config.yaml`:

```yaml
capture:
  interface: eth0

web:
  host: 0.0.0.0
  port: 8080
```

Start manually in monitor mode:

```bash
cd /path/to/AI-driven-firewall-for-LAN-wLAN-analysis
sudo ./venv/bin/python run.py \
  --config ./config.yaml \
  --iface eth0 \
  --mode monitor \
  --port 8080
```

Use the actual LAN interface instead of `eth0`. The explicit `--port 8080`
keeps this project's dashboard separate from services using port 80.

### G. Verify live traffic

In another Pi terminal:

```bash
sudo ss -ltnp | grep ':8080'
curl -s http://192.168.50.1:8080/api/health
curl -s http://192.168.50.1:8080/api/model
curl -s http://192.168.50.1:8080/api/summary
```

From the test client, generate traffic:

```bash
ping -c 3 1.1.1.1
curl -I https://example.com
nslookup example.com
```

On the Pi, confirm packets arrive on the selected LAN interface:

```bash
sudo tcpdump -ni eth0 'ip and (tcp or udp)'
```

Open `http://192.168.50.1:8080/`. The packet count, flow count,
throughput, charts, and tables should update every refresh interval.

The expected live path is:

```text
client -> LAN interface -> Scapy -> flow meter -> model -> SQLite/API -> browser
```

If `tcpdump` shows no client packets, fix the physical topology or client
gateway before changing the application. If packets are visible but the API
does not change, inspect:

```bash
journalctl -u idsfw -n 100 --no-pager
curl -s 'http://192.168.50.1:8080/api/timeseries?points=10'
```

The model endpoint must report `tf` or `tflite`, never `mock` for live
operation.

### H. Enable systemd after the manual test

Stop the foreground process with `Ctrl+C`. Confirm that this project's
`config.yaml` contains the correct interface and port, then:

```bash
sudo systemctl enable --now idsfw
sudo systemctl status idsfw --no-pager
journalctl -u idsfw -f
```

The service must start with this project's virtual environment and
`config.yaml`. It does not replace or control Pi-hole's services.

### H.1 Run controls: foreground or background

Use **foreground mode** during the first test. It keeps logs in the terminal
and is stopped with `Ctrl+C`:

```bash
sudo ./venv/bin/python run.py \
  --config ./config.yaml \
  --iface eth0 \
  --mode monitor \
  --port 8080
```

Press `Ctrl+C` once to request a clean shutdown. The capture and worker
threads will stop before the process exits.

For normal background operation, use the project's systemd service:

```bash
sudo systemctl start idsfw
sudo systemctl status idsfw --no-pager
```

Enable automatic startup after reboot:

```bash
sudo systemctl enable idsfw
```

Enable and start it in one command:

```bash
sudo systemctl enable --now idsfw
```

Follow background logs:

```bash
journalctl -u idsfw -f
```

Stop the background server when needed:

```bash
sudo systemctl stop idsfw
```

Restart it after changing `config.yaml`:

```bash
sudo systemctl restart idsfw
```

Disable automatic startup without stopping a currently running process:

```bash
sudo systemctl disable idsfw
```

Stop and disable it together:

```bash
sudo systemctl disable --now idsfw
```

Check whether it is running:

```bash
systemctl is-active idsfw
systemctl is-enabled idsfw
```

Do not run the foreground command and the systemd service at the same time;
both instances will attempt to capture the interface and bind the dashboard
port. If port `8080` is already in use, identify the process with:

```bash
sudo ss -ltnp | grep ':8080'
```

If it is this project's systemd process, stop it before starting a foreground
test:

```bash
sudo systemctl stop idsfw
```

### I. Move from monitor to blocking

After live monitoring works, test manual blocking:

```bash
sudo ./venv/bin/python run.py \
  --config ./config.yaml \
  --iface eth0 \
  --mode manual \
  --port 8080
```

Only after reviewing false positives should automatic blocking be considered:

```bash
sudo ./venv/bin/python run.py \
  --config ./config.yaml \
  --iface eth0 \
  --mode auto \
  --port 8080
```

Never flush the complete nftables ruleset on a Pi hosting other services.
Inspect and remove only this project's `idsfw` rules during rollback.
