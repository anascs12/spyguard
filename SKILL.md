---
name: privacy-scanner
license: Apache-2.0. See LICENSE file for details.
description: "Scan WiFi networks to detect hidden cameras and surveillance devices in rental accommodations (Airbnb, Booking, VRBO, etc.). Use when: user wants to check for hidden cameras, scan for surveillance devices, verify rental camera policy compliance, or run a privacy audit of a rental property. TRIGGER on: 'scan for cameras', 'hidden camera', 'surveillance scan', 'privacy scan', 'privacy check rental', 'check for spy devices', 'scan wifi cameras', 'privacy scanner'. DO NOT TRIGGER on: general network troubleshooting, WiFi speed tests, or unrelated security audits."
---

# Privacy Scanner — WiFi Surveillance Device Detector

Defensive security tool that scans the local WiFi network to detect hidden cameras, microphones, and surveillance devices in rental accommodations (Airbnb, Booking, VRBO, etc.).

## Overview

Airbnb's policy **prohibits ALL indoor cameras and recording devices**, even if disclosed and even if turned off. This tool helps guests verify compliance by scanning the WiFi network for surveillance equipment.

The scanner runs 7 phases: host discovery → manufacturer identification → port scanning → service discovery → deep inspection → risk classification → report generation.

**What it detects:**
- IP cameras from known surveillance manufacturers (Hikvision, Dahua, EZVIZ, Amcrest, etc.)
- Consumer cameras (Wyze, Blink, Arlo, Nest, Ring, Foscam, Yi, Eufy)
- Hidden cameras using generic IoT chipsets (ESP32, Realtek, MediaTek)
- RTSP streaming services, camera web interfaces, vendor-specific protocols
- ONVIF-compatible devices, mDNS-advertising cameras, UPnP media devices

**What it CANNOT detect:**
- Cameras on a separate VLAN or wired-only network
- Cellular-connected cameras (4G/LTE)
- Cameras powered off or in standby
- Devices using MAC address randomization
- Local-storage cameras not connected to any network
- Audio-only recording devices

## Workflow

### Step 1: Check Prerequisites

**CRITICAL**: `nmap` is mandatory on all platforms. Python 3.8+ is required for the cross-platform scanner.

Install per platform:
- **Linux (Arch)**: `sudo pacman -S nmap python arp-scan avahi`
- **Linux (Debian)**: `sudo apt install nmap python3 arp-scan avahi-utils`
- **macOS**: `brew install nmap python arp-scan`
- **Windows**: Install nmap from https://nmap.org/download (includes Npcap), Python from https://python.org

Python packages (optional, improve detection):
```bash
pip install python-nmap zeroconf requests
```

### Step 2: Run the Scanner

**Cross-platform (recommended)** — works on Linux, macOS, and Windows:
```bash
# Linux / macOS
sudo python3 scripts/scan.py

# Windows (Admin PowerShell)
python scripts\scan.py
```

**Linux-only** — bash version (full feature parity):
```bash
sudo bash scripts/scan.sh
```

**Common flags** (same for both scan.py and scan.sh):
```bash
# Quick scan (~2-3 minutes)
sudo python3 scripts/scan.py --quick

# Report in English or Spanish (default: Portuguese)
sudo python3 scripts/scan.py --lang en
sudo python3 scripts/scan.py --lang es

# Specify interface/subnet manually
sudo python3 scripts/scan.py --interface wlan0 --subnet 192.168.1.0/24
```

**CRITICAL**: Run with `sudo` (Linux/macOS) or as Administrator (Windows). ARP scanning and SYN port scanning require elevated privileges. Without them, the scanner falls back to less reliable methods.

### Step 3: Go beyond the connected network

A full scan also covers nearby WiFi access points (camera hotspots), Bluetooth LE trackers, and,
on Linux with root, a passive monitor-mode capture that flags cameras on **any** nearby network.

```bash
sudo python3 scripts/scan.py --monitor wlan1          # second USB adapter = all channels
sudo python3 scripts/scan.py --locate mon:<MAC>       # live hot/cold meter to find a device
sudo python3 scripts/scan.py --survey mon:<MAC>       # measure from 3+ spots -> position estimate
python3 scripts/scan.py --optical 0                   # offline/powered-off cameras via lens glint & IR
sudo python3 scripts/scan.py --watch 10 --evidence    # keep watching; save hashed evidence pack
python3 scripts/scan.py --trust <MAC>=my-phone        # never flag the user's own devices
```

All checks are detection-only. Never suggest logging into a device, guessing passwords,
deauthenticating clients or joining someone else's network.

### Step 4: Interpret Results

The scanner classifies every device into risk levels:

| Risk | Icon | Meaning | Action |
|------|------|---------|--------|
| CRITICAL | 🔴 | Confirmed camera/streaming device | **Photograph. Contact Airbnb. Consider leaving.** |
| HIGH | 🟠 | Strong camera indicators | Investigate physically. Check if disclosed in listing. |
| MODERATE | 🟡 | Suspicious/unidentified device | Try to locate and identify the device. |
| LOW | 🟢 | Probably safe (IoT, chipset device) | No action needed unless suspicious location. |
| INFO | 🔵 | Known safe device | No action needed. |

### Step 5: Take Action (if threats found)

For CRITICAL or HIGH findings:
1. **Do NOT** disconnect or tamper with the device
2. **Photograph** the device and its location
3. **Save** the scan report (terminal output + HTML file in `./privacy-scan-results/`)
4. **Contact Airbnb**: App → Your Trips → Get Help → Report a safety concern
5. **Airbnb Emergency**: +1-855-424-7262
6. If you feel unsafe, **leave the property**
7. Consider contacting **local law enforcement**

## Scanning Phases

| Phase | Name | Tool | Purpose |
|-------|------|------|---------|
| 1 | Host Discovery | `arp-scan`, `nmap -sn` | Find ALL devices on the network |
| 2 | OUI Analysis | nmap-mac-prefixes + embedded DB | Identify manufacturers, flag camera brands |
| 3 | Port Scan | `nmap -sS/-sT -sV` | Scan camera-specific ports (RTSP, HTTP, vendor) |
| 4 | Service Discovery | zeroconf/`avahi-browse`, WS-Discovery | mDNS, UPnP, ONVIF (+ model lookup) |
| 4b | Nearby Wireless | `nmcli`/`iw`/`netsh`, `bleak` | Camera hotspots, BLE trackers/cameras |
| 5 | Deep Inspection | `requests`/`curl`, RTSP handshake | HTTP fingerprint, RTSP verify, open streams |
| 5b | Over-the-Air | monitor mode, `scapy`/`tcpdump` | Cameras on any nearby network (Linux, root) |
| 6 | Classification | Evidence correlation | Apply risk matrix to all collected evidence |
| 7 | Report | Terminal + HTML | Formatted output with actionable recommendations |

Phases 4-5 are skipped in `--quick` mode.

## Risk Classification Matrix

| Condition | Risk Level |
|-----------|-----------|
| Surveillance manufacturer OUI + RTSP/streaming port open | 🔴 CRITICAL |
| Surveillance manufacturer OUI + camera web UI confirmed | 🔴 CRITICAL |
| Any device + confirmed RTSP handshake | 🔴 CRITICAL |
| RTSP video stream reachable without password | 🔴 CRITICAL |
| Device answers ONVIF discovery as a video transmitter | 🔴 CRITICAL |
| Camera-brand hotspot with camera SSID nearby | 🔴 CRITICAL |
| Camera-brand device streaming over the air, close by | 🔴 CRITICAL |
| Camera service advertising via mDNS (e.g. `_rtsp._tcp`) | 🔴 CRITICAL |
| Camera web page title (NETSurveillance, IPCamera, DVR, etc.) | 🔴 CRITICAL |
| Known surveillance manufacturer, no open ports detected | 🟠 HIGH |
| Known consumer camera brand (Wyze, Blink, Arlo, etc.) | 🟠 HIGH |
| Manufacturer name contains camera/surveillance keywords | 🟠 HIGH |
| Unknown device + RTSP port open | 🟠 HIGH |
| Unknown device + proprietary camera port (37777, 34567, 34599) | 🟠 HIGH |
| Camera-like hostname or mDNS name | 🟠 HIGH |
| Camera setup hotspot / camera-brand AP nearby | 🟠 HIGH |
| AirTag (separated) / Google Find My tracker | 🟠 HIGH |
| Close device on another network with continuous upload | 🟠 HIGH |
| Port 8000/8200/9000 only (also common on non-cameras) | 🟡 MODERATE |
| IoT chipset (Espressif, Tuya) + camera ports open | 🟡 MODERATE |
| IoT chipset + HTTP server (no camera keywords) | 🟡 MODERATE |
| Unknown manufacturer + HTTP server | 🟡 MODERATE |
| Completely unidentified device | 🟡 MODERATE |
| IoT chipset, no camera ports | 🟢 LOW |
| Generic network chipset | 🟢 LOW |
| Known safe manufacturer (Apple, Samsung, Intel, Dell, etc.) | 🔵 INFO |
| Identified non-camera device | 🔵 INFO |

## Critical Rules

- **CRITICAL**: Always run with `sudo`. ARP scans and SYN scans require root.
- **CRITICAL**: Never skip Phase 2 (OUI analysis). Manufacturer ID is the strongest signal.
- **CRITICAL**: Scan ALL devices, not just flagged ones. Cameras often use generic chipset MACs.
- **CRITICAL**: Use `-T4` timing (aggressive but safe). Do NOT use `-T5` — IoT devices may crash.
- **CRITICAL**: Always mention scan limitations in the report. This is not a comprehensive physical sweep.
- **CRITICAL**: Do NOT advise the user to disconnect or tamper with found devices — this could destroy evidence.

## Common Pitfalls

❌ **WRONG**: Scanning only devices with suspicious OUI
✅ **CORRECT**: Scan ALL devices — cheap cameras use generic Espressif/Realtek MACs

❌ **WRONG**: Trusting only OUI lookup for device identification
✅ **CORRECT**: Correlate OUI + ports + HTTP fingerprint + mDNS for accurate classification

❌ **WRONG**: Only checking port 554 for cameras
✅ **CORRECT**: Check ALL camera ports including vendor-specific (37777, 34567, 8000, 9000, etc.)

❌ **WRONG**: Ignoring mDNS services
✅ **CORRECT**: Many cameras announce `_rtsp._tcp` or `_camera._tcp` via Bonjour

❌ **WRONG**: Concluding "no cameras" after a clean scan
✅ **CORRECT**: State that the WiFi scan was clean BUT cameras could exist on other networks, wired, or offline

## Camera-Specific Ports

```
554     - RTSP (primary camera streaming)
8554    - RTSP alternate
80/443  - HTTP/HTTPS (camera web UI)
8080    - HTTP alternate (very common on cameras)
8443    - HTTPS alternate
8000    - Hikvision ISAPI/SDK
8200    - Hikvision web alternate
37777   - Dahua proprietary protocol
34567   - XMEye/Chinese NVR protocol
34599   - XMEye alternate
9000    - Reolink proprietary
3702    - ONVIF WS-Discovery
1935    - RTMP streaming
5000    - Synology/QNAP Surveillance Station
6667    - RTSP alternate
8899    - HTTP camera alternate
7070    - Streaming alternate
9527    - Chinese camera debug port
```

## Reference Files

- `reference/oui-database.md` — Curated camera manufacturer MAC prefixes (3 tiers)
- `reference/ports-services.md` — Camera ports, HTTP keywords, RTSP paths, mDNS services
- `reference/device-signatures.md` — HTTP headers, HTML titles, mDNS hostnames, UPnP patterns

## Output

The scanner produces:
1. **Terminal output** — Color-coded, real-time progress with risk-classified device list
2. **HTML report** — Saved to `./privacy-scan-results/privacy-scan-YYYYMMDD-HHMMSS.html`
   - Dark security-themed UI with interactive device cards
   - Language switcher (PT/EN/ES) — works offline, no reload needed
   - Copy-to-clipboard for IP/MAC addresses
   - Print-friendly mode
3. **Raw data** — Saved to `./privacy-scan-results/raw-data-YYYYMMDD-HHMMSS/`

## Rental Platform Policies

Major short-term rental platforms prohibit indoor surveillance cameras:

| Platform | Policy | Link |
|----------|--------|------|
| **Airbnb** | All indoor cameras prohibited, even if off. Hidden cameras always banned. Outdoor cameras must be disclosed. | [airbnb.com/help/article/3061](https://www.airbnb.com/help/article/3061) |
| **Booking.com** | Cameras allowed only in common/public areas, must be visible and disclosed. Prohibited where guests expect privacy. | [partner.booking.com/...surveillance-devices](https://partner.booking.com/en-us/help/legal-security/security/requirements-and-regulations-surveillance-devices) |
| **Vrbo** | Indoor cameras prohibited. Outdoor cameras allowed only for security at access points, must be disclosed. | [vrbo.com/...use-of-surveillance-policy](https://www.vrbo.com/tlp/trust-and-safety/use-of-surveillance-policy) |
