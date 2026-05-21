# Network Scanner

A Python tool that scans a local network IP range using ARP requests and lists all active devices along with their IP and MAC addresses. Linux only.

> **Disclaimer:** For educational purposes and authorized testing only. Only use on networks you own or have explicit permission to scan. The author is not responsible for any misuse.

---

## How it works

1. Sends ARP broadcast requests to every IP in the target range
2. Collects responses from active devices
3. Displays each device's IP address and MAC address in a table

## Requirements

```bash
pip install -r requirements.txt
```

> **Note:** Linux only. Requires root privileges.

## Usage

```bash
sudo python3 network_scanner.py -t <ip_or_range>
```

**Single IP:**
```bash
sudo python3 network_scanner.py -t 192.168.1.1
```

**IP range:**
```bash
sudo python3 network_scanner.py -t 192.168.1.1/24
```

**Example output:**
```
---------------------------------------------
IP                      MAC Address
---------------------------------------------
192.168.1.1             aa:bb:cc:dd:ee:ff
192.168.1.5             11:22:33:44:55:66
```

---

## Part of [H-Tools](https://github.com/shubham-patel/H-Tools)

Built during B.Tech studies. H-Tools bundles this and other networking/security utilities in a single CLI menu.
