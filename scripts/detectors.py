#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Extended detectors for privacy-scanner.

These checks look beyond the WiFi network the scanner is connected to:

  - RTSP protocol probing (real OPTIONS/DESCRIBE handshake, no credentials)
  - ONVIF WS-Discovery + unauthenticated GetDeviceInformation
  - Nearby WiFi access points (camera hotspots, camera-brand BSSIDs)
  - Passive 802.11 monitor-mode capture (cameras on OTHER networks)
  - Bluetooth LE (trackers, BLE-provisioned cameras)
  - Live "hot/cold" locator by RSSI or latency

Everything here is detection-only: nothing logs in, guesses passwords,
joins foreign networks, deauthenticates clients or decrypts traffic.

This module never imports scan.py; callers pass an ``oui_lookup(mac)``
callback returning ``(manufacturer, tier)`` where tier is
1 = surveillance brand, 2 = consumer camera brand, 3 = camera keyword
in manufacturer name, 0 = other/unknown, -1 = randomized MAC.
"""

from __future__ import annotations

import platform
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import uuid
from typing import Callable

SYSTEM = platform.system()

OuiLookup = Callable[[str], "tuple[str, int]"]


def _run(cmd: list[str], timeout: int = 20) -> tuple[str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr, r.returncode
    except (OSError, subprocess.TimeoutExpired):
        return "", 1


def finding(risk: str, source: str, mac: str, manufacturer: str, device_type: str,
            evidence: str, recommendation: str) -> dict:
    """Build a classification record compatible with scan.py's phase 6 output."""
    return {
        "risk": risk, "ip": source, "mac": mac, "manufacturer": manufacturer,
        "device_type": device_type, "open_ports": "", "evidence": evidence,
        "recommendation": recommendation, "source": source,
    }


def proximity(dbm: float | None) -> str:
    """Rough distance hint from received signal strength."""
    if dbm is None:
        return "signal unknown"
    if dbm >= -55:
        return f"{dbm:.0f} dBm — very close (likely same room/unit)"
    if dbm >= -70:
        return f"{dbm:.0f} dBm — nearby (same or adjacent unit)"
    return f"{dbm:.0f} dBm — far (likely a neighbour)"


# Device names used by cameras in setup/hotspot mode and by cheap spy cameras
CAMERA_NAME_STRONG = re.compile(
    r"^(?:IPC|IPCAM|IP[-_ ]?CAM|HAP-|CAM[-_]|EZVIZ|HIK|DAHUA|DH[-_]IPC|WYZE|"
    r"YI[-_]|YICAM|TAPO[-_ ]?C|TP-LINK_IPC|V380|MV\d{6}|HDWIFICAM|WIFI[-_ ]?CAM|"
    r"LOOKCAM|JOVISION|REOLINK|IMOU|ICSEE|XM[-_]|CLOUDCAM|SMART[-_ ]?CAM|LIVECAM|"
    r"MINICAM|MINI[-_ ]CAM|HD[-_]?CAM|CAMHI|P2PCAM|ANBIUX|ESP32[-_]?CAM|"
    r"NVR|DVR|EUFY[-_ ]?CAM|BLINK|ARLO|AMCREST|FOSCAM|SPYCAM)",
    re.IGNORECASE,
)
CAMERA_NAME_WEAK = re.compile(r"\b(?:cam|camera|ipcam|webcam|spy|nanny|cctv|surveillance)\b",
                              re.IGNORECASE)


# ===========================================================================
# RTSP
# ===========================================================================

RTSP_PATHS = [
    "/", "/live", "/live/ch00_0", "/h264", "/stream1", "/11", "/onvif1",
    "/Streaming/Channels/101", "/cam/realmonitor?channel=1&subtype=0",
    "/videoMain", "/ch0_0.h264",
]


def _rtsp_request(ip: str, port: str, method: str, path: str, cseq: int,
                  timeout: float = 4.0) -> str:
    req = (f"{method} rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
           f"CSeq: {cseq}\r\nUser-Agent: privacy-scanner\r\n")
    if method == "DESCRIBE":
        req += "Accept: application/sdp\r\n"
    req += "\r\n"
    data = b""
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(req.encode())
            while len(data) < 16384:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                head, sep, body = data.partition(b"\r\n\r\n")
                if sep:
                    m = re.search(rb"(?i)content-length:\s*(\d+)", head)
                    if not m or len(body) >= int(m.group(1)):
                        break
    except OSError:
        pass
    return data.decode("latin-1", errors="replace")


def _rtsp_header(resp: str, name: str) -> str:
    m = re.search(rf"(?im)^{name}:\s*(.+?)\s*$", resp)
    return m.group(1) if m else ""


def _rtsp_status(resp: str) -> int:
    m = re.match(r"RTSP/1\.\d\s+(\d{3})", resp)
    return int(m.group(1)) if m else 0


def probe_rtsp(ip: str, port: str) -> dict | None:
    """Speak RTSP to ip:port. Returns None if it is not an RTSP server.

    Result keys: server, methods, auth_required, open_stream (path of a
    stream whose SDP advertises video without credentials, or "").
    Only OPTIONS and DESCRIBE are sent; no media is ever requested.
    """
    resp = _rtsp_request(ip, port, "OPTIONS", "/", 1)
    if not resp.startswith("RTSP/1."):
        return None
    result = {
        "server": _rtsp_header(resp, "Server"),
        "methods": _rtsp_header(resp, "Public"),
        "auth_required": False,
        "open_stream": "",
    }
    for cseq, path in enumerate(RTSP_PATHS, start=2):
        desc = _rtsp_request(ip, port, "DESCRIBE", path, cseq)
        status = _rtsp_status(desc)
        if status == 200 and "m=video" in desc:
            result["open_stream"] = path
            break
        if status == 401:
            result["auth_required"] = True
            break
    return result


# ===========================================================================
# ONVIF
# ===========================================================================

_WSD_PROBE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
    'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
    'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
    'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
    '<e:Header><w:MessageID>uuid:{msgid}</w:MessageID>'
    '<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
    '<w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>'
    '</e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types>'
    '</d:Probe></e:Body></e:Envelope>'
)

_ONVIF_DEVINFO = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
    '<GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/>'
    '</s:Body></s:Envelope>'
)


def onvif_discover(bind_ip: str = "", timeout: float = 4.0) -> list[dict]:
    """Multicast WS-Discovery probe for ONVIF video transmitters."""
    found: dict[str, dict] = {}
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        if bind_ip:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(bind_ip))
        sock.settimeout(0.5)
        sock.sendto(_WSD_PROBE.format(msgid=uuid.uuid4()).encode(), ("239.255.255.250", 3702))
    except OSError:
        return []

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            data, addr = sock.recvfrom(65535)
        except socket.timeout:
            continue
        except OSError:
            break
        text = data.decode("utf-8", errors="replace")
        if "ProbeMatch" not in text:
            continue
        xaddrs = re.search(r"<[^>]*XAddrs>([^<]+)<", text)
        scopes = re.search(r"<[^>]*Scopes[^>]*>([^<]+)<", text)
        entry = {"ip": addr[0], "xaddrs": xaddrs.group(1).split() if xaddrs else [],
                 "name": "", "hardware": "", "manufacturer": "", "model": "", "firmware": ""}
        for scope in (scopes.group(1).split() if scopes else []):
            scope = urllib.parse.unquote(scope)
            for key in ("name", "hardware"):
                m = re.search(rf"onvif://www\.onvif\.org/{key}/(.+)", scope)
                if m:
                    entry[key] = m.group(1)
        found[addr[0]] = entry
    sock.close()

    for entry in found.values():
        for xaddr in entry["xaddrs"]:
            if xaddr.startswith("http://"):
                entry.update({k: v for k, v in onvif_device_info(xaddr).items() if v})
                break
    return list(found.values())


def onvif_device_info(xaddr: str, timeout: float = 4.0) -> dict:
    """Unauthenticated GetDeviceInformation. Many cameras answer without login."""
    req = urllib.request.Request(
        xaddr, data=_ONVIF_DEVINFO.encode(),
        headers={"Content-Type": "application/soap+xml; charset=utf-8"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read(65536).decode("utf-8", errors="replace")
    except Exception:
        return {}
    info = {}
    for key, tag in (("manufacturer", "Manufacturer"), ("model", "Model"),
                     ("firmware", "FirmwareVersion")):
        m = re.search(rf"<(?:\w+:)?{tag}>([^<]*)</", text)
        info[key] = m.group(1).strip() if m else ""
    return info


# ===========================================================================
# Nearby WiFi access points (managed-mode scan, no monitor mode needed)
# ===========================================================================

def _pct_to_dbm(pct: str) -> float | None:
    try:
        return int(pct) / 2 - 100
    except ValueError:
        return None


def scan_wifi_aps(iface: str = "") -> list[dict]:
    """List nearby access points: bssid, ssid, signal_dbm, channel."""
    aps: list[dict] = []
    if SYSTEM == "Linux" and shutil.which("nmcli"):
        cmd = ["nmcli", "-t", "-e", "yes", "-f", "BSSID,SSID,CHAN,SIGNAL",
               "dev", "wifi", "list", "--rescan", "yes"]
        if iface:
            cmd += ["ifname", iface]
        out, rc = _run(cmd, timeout=30)
        for line in out.splitlines():
            parts = [p.replace("\\:", ":").replace("\\\\", "\\")
                     for p in re.split(r"(?<!\\):", line)]
            if len(parts) >= 4 and re.fullmatch(r"[0-9A-Fa-f:]{17}", parts[0]):
                aps.append({"bssid": parts[0].upper(), "ssid": parts[1],
                            "channel": parts[2], "signal_dbm": _pct_to_dbm(parts[3])})
    if not aps and SYSTEM == "Linux" and shutil.which("iw") and iface:
        out, _ = _run(["iw", "dev", iface, "scan"], timeout=30)
        cur: dict | None = None
        for line in out.splitlines():
            m = re.match(r"BSS ([0-9a-f:]{17})", line)
            if m:
                cur = {"bssid": m.group(1).upper(), "ssid": "", "channel": "", "signal_dbm": None}
                aps.append(cur)
            elif cur is not None:
                line = line.strip()
                if line.startswith("signal:"):
                    cur["signal_dbm"] = float(line.split()[1])
                elif line.startswith("SSID:"):
                    cur["ssid"] = line[5:].strip()
                elif "primary channel:" in line or "DS Parameter set: channel" in line:
                    cur["channel"] = line.split()[-1]
    elif SYSTEM == "Darwin":
        airport = ("/System/Library/PrivateFrameworks/Apple80211.framework/"
                   "Versions/Current/Resources/airport")
        out, _ = _run([airport, "-s"], timeout=30)
        for line in out.splitlines():
            m = re.match(r"^\s*(.*?)\s+([0-9a-f:]{17})\s+(-\d+)\s+(\S+)", line)
            if m:
                aps.append({"bssid": m.group(2).upper(), "ssid": m.group(1),
                            "channel": m.group(4).split(",")[0], "signal_dbm": float(m.group(3))})
    elif SYSTEM == "Windows":
        out, _ = _run(["netsh", "wlan", "show", "networks", "mode=bssid"], timeout=30)
        ssid = ""
        cur = None
        for line in out.splitlines():
            line = line.strip()
            if re.match(r"SSID \d+\s*:", line):
                ssid = line.split(":", 1)[1].strip()
            elif re.match(r"BSSID \d+\s*:", line):
                cur = {"bssid": line.split(":", 1)[1].strip().upper(), "ssid": ssid,
                       "channel": "", "signal_dbm": None}
                aps.append(cur)
            elif cur is not None and line.startswith("Signal"):
                cur["signal_dbm"] = _pct_to_dbm(line.split(":", 1)[1].strip().rstrip("%"))
            elif cur is not None and line.startswith("Channel"):
                cur["channel"] = line.split(":", 1)[1].strip()
    return aps


def classify_aps(aps: list[dict], oui_lookup: OuiLookup) -> list[dict]:
    """Flag access points that look like cameras or camera hotspots."""
    results = []
    for ap in aps:
        mfr, tier = oui_lookup(ap["bssid"])
        ssid = ap.get("ssid", "")
        strong = bool(CAMERA_NAME_STRONG.search(ssid))
        weak = bool(CAMERA_NAME_WEAK.search(ssid))
        brand = tier in (1, 2, 3)
        where = proximity(ap.get("signal_dbm"))
        label = f"SSID '{ssid}'" if ssid else "hidden SSID"
        ev = f"{label}, BSSID {ap['bssid']}, channel {ap.get('channel') or '?'}, {where}"

        if brand and strong:
            risk, dtype = "CRITICAL", "Camera hotspot (brand + camera SSID)"
        elif brand:
            risk, dtype = "HIGH", "Camera-brand access point nearby"
        elif strong:
            risk, dtype = "HIGH", "Camera setup/hotspot network nearby"
        elif weak:
            risk, dtype = "MODERATE", "Network with camera-like name"
        else:
            continue
        results.append(finding(
            risk, "nearby-wifi", ap["bssid"], mfr or "Unknown", dtype,
            f"{ev}. Cameras broadcast their own network in setup mode or for phone pairing.",
            "Not on your network: use '--locate wifi:<BSSID>' and walk around to find it.",
        ))
    return results


# ===========================================================================
# Bluetooth LE
# ===========================================================================

def _uuid16(u: str) -> str:
    u = u.lower()
    if len(u) == 36 and u.endswith("-0000-1000-8000-00805f9b34fb"):
        return u[4:8]
    return u


def scan_ble(duration: float = 12.0) -> list[dict] | None:
    """Return advertising BLE devices, or None if bleak isn't installed."""
    try:
        import asyncio
        from bleak import BleakScanner
    except ImportError:
        return None

    async def _discover():
        return await BleakScanner.discover(timeout=duration, return_adv=True)

    found = asyncio.run(_discover())
    devices = []
    for addr, (dev, adv) in found.items():
        devices.append({
            "address": addr,
            "name": adv.local_name or dev.name or "",
            "rssi": adv.rssi,
            "manufacturer_data": {k: bytes(v) for k, v in adv.manufacturer_data.items()},
            "services": {_uuid16(u) for u in adv.service_uuids},
            "service_data": {_uuid16(k): bytes(v) for k, v in adv.service_data.items()},
        })
    return devices


def classify_ble(devices: list[dict]) -> list[dict]:
    """Flag trackers and BLE-provisioned cameras."""
    results = []
    for d in devices:
        name, rssi = d["name"], d["rssi"]
        apple = d["manufacturer_data"].get(0x004C, b"")
        svcs = d["services"] | set(d["service_data"])
        fmdn = d["service_data"].get("feaa", b"")
        where = proximity(rssi)
        close = rssi is not None and rssi >= -70
        hit = None
        # Find My offline beacon: 0x12, length 0x19 = separated from owner
        # (0x02 = near its owner). Status bits 4-5: 0 Apple device, 1 AirTag,
        # 2 Find My accessory, 3 AirPods. Only separated tags are trackers.
        if apple[:2] == b"\x12\x19" and len(apple) > 2 and (apple[2] >> 4) & 0x3 in (1, 2):
            kind = "AirTag" if (apple[2] >> 4) & 0x3 == 1 else "Find My accessory"
            hit = ("HIGH" if close else "LOW", f"Apple {kind} away from its owner",
                   "Broadcasting the 'separated from owner' Find My beacon")
        elif fmdn[:1] in (b"\x40", b"\x41"):
            hit = ("HIGH" if close else "LOW", "Google Find My Device tracker",
                   "Broadcasting a Find My Device network beacon")
        elif svcs & {"feed", "feec"}:
            hit = ("MODERATE" if close else "LOW", "Tile tracker", "Advertising Tile service UUID")
        elif "fd5a" in svcs:
            hit = ("MODERATE" if close else "LOW", "Samsung SmartTag", "Advertising SmartTag service UUID")
        elif "fe33" in svcs:
            hit = ("MODERATE" if close else "LOW", "Chipolo tracker", "Advertising Chipolo service UUID")
        elif name and CAMERA_NAME_STRONG.search(name):
            hit = ("HIGH", "BLE device with camera name",
                   f"Camera-style BLE name '{name}' (BLE is used to set up cameras)")
        elif name and CAMERA_NAME_WEAK.search(name):
            hit = ("MODERATE", "BLE device with camera-like name", f"BLE name '{name}'")
        if hit:
            risk, dtype, why = hit
            results.append(finding(
                risk, "ble", d["address"], name or "Unknown", dtype, f"{why}; {where}",
                f"Use '--locate ble:{d['address']}' and walk around to find it.",
            ))
    return results


# ===========================================================================
# Passive 802.11 monitor-mode capture (Linux)
# ===========================================================================

CHANNELS_24 = list(range(1, 14))
CHANNELS_5 = [36, 40, 44, 48, 149, 153, 157, 161, 165]
MON_IFACE = "psmon0"


def monitor_supported(iface: str) -> bool:
    """True if iface's radio advertises monitor mode (Linux, iw)."""
    if SYSTEM != "Linux" or not shutil.which("iw"):
        return False
    out, rc = _run(["iw", "dev", iface, "info"])
    m = re.search(r"wiphy (\d+)", out)
    if rc != 0 or not m:
        return False
    phy, _ = _run(["iw", "phy", f"phy{m.group(1)}", "info"])
    modes = re.search(r"Supported interface modes:\s*\n((?:\s+\* .+\n)+)", phy)
    return bool(modes and re.search(r"\* monitor\b", modes.group(1)))


class MonitorCapture:
    """Channel-hopping passive capture that tracks stations and APs."""

    def __init__(self, iface: str, log: Callable[[str], None] = print):
        self.iface = iface
        self.mon = iface
        self.created = False
        self.log = log
        self.channel = 0
        self.locked = False
        self.dwell: dict[int, float] = {}
        self.stations: dict[str, dict] = {}
        self.aps: dict[str, dict] = {}
        self.target = ""
        self.on_target: Callable[[float | None, int], None] | None = None
        self._stop = threading.Event()

    # -- setup -------------------------------------------------------------
    def setup(self) -> bool:
        out, _ = _run(["iw", "dev", self.iface, "info"])
        if "type monitor" in out:
            return True
        out, rc = _run(["iw", "dev", self.iface, "interface", "add", MON_IFACE, "type", "monitor"])
        if rc != 0:
            self.log(f"Could not create monitor interface: {out.strip()}")
            return False
        self.created = True
        self.mon = MON_IFACE
        _run(["ip", "link", "set", MON_IFACE, "up"])
        return True

    def teardown(self) -> None:
        if self.created:
            _run(["iw", "dev", MON_IFACE, "del"])
            self.created = False

    # -- channel hopping ---------------------------------------------------
    def _hop(self, dwell: float) -> None:
        usable = []
        for ch in CHANNELS_24 + CHANNELS_5:
            _, rc = _run(["iw", "dev", self.mon, "set", "channel", str(ch)], timeout=5)
            if rc == 0:
                usable.append(ch)
        if len(usable) <= 1:
            self.locked = True
            out, _ = _run(["iw", "dev", self.mon, "info"])
            m = re.search(r"channel (\d+)", out)
            self.channel = int(m.group(1)) if m else 0
            while not self._stop.wait(0.5):
                self.dwell[self.channel] = self.dwell.get(self.channel, 0) + 0.5
            return
        while not self._stop.is_set():
            for ch in usable:
                if self._stop.is_set():
                    return
                if self.target and self.target in self.stations and self.channel:
                    # Locator mode: stay on the target's channel once seen
                    self._stop.wait(dwell)
                    continue
                _run(["iw", "dev", self.mon, "set", "channel", str(ch)], timeout=5)
                self.channel = ch
                start = time.time()
                self._stop.wait(dwell)
                self.dwell[ch] = self.dwell.get(ch, 0) + time.time() - start

    # -- frame accounting --------------------------------------------------
    def _seen_ap(self, bssid: str, ssid: str, rssi: float | None) -> None:
        ap = self.aps.setdefault(bssid.upper(), {"ssid": ssid, "rssi": rssi, "channel": self.channel})
        if ssid:
            ap["ssid"] = ssid
        if rssi is not None and (ap["rssi"] is None or rssi > ap["rssi"]):
            ap["rssi"] = rssi

    def _seen_data(self, sta: str, bssid: str, up: bool, size: int, rssi: float | None) -> None:
        sta = sta.upper()
        if int(sta[:2], 16) & 0x01:  # multicast/broadcast address, not a station
            return
        s = self.stations.setdefault(sta, {
            "bssid": bssid.upper(), "channel": self.channel, "rssi": None,
            "up_frames": 0, "down_frames": 0, "up_bytes": 0, "down_bytes": 0,
        })
        if up:
            s["up_frames"] += 1
            s["up_bytes"] += size
            if rssi is not None and (s["rssi"] is None or rssi > s["rssi"]):
                s["rssi"] = rssi
            if self.on_target and sta == self.target:
                self.on_target(rssi, self.channel)
        else:
            s["down_frames"] += 1
            s["down_bytes"] += size

    # -- capture backends --------------------------------------------------
    def _capture_scapy(self, duration: float) -> bool:
        try:
            from scapy.all import Dot11, Dot11Elt, sniff  # type: ignore
        except ImportError:
            return False

        def handle(pkt):
            if not pkt.haslayer(Dot11):
                return
            d = pkt[Dot11]
            rssi = getattr(pkt, "dBm_AntSignal", None)
            if d.type == 0 and d.subtype in (5, 8) and d.addr3:
                ssid = ""
                if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].ID == 0:
                    ssid = pkt[Dot11Elt].info.decode("utf-8", errors="replace")
                self._seen_ap(d.addr3, ssid, rssi)
            elif d.type == 2 and d.addr1 and d.addr2:
                fc = int(d.FCfield)
                if fc & 0x3 == 0x1:
                    self._seen_data(d.addr2, d.addr1, True, len(pkt), rssi)
                elif fc & 0x3 == 0x2:
                    self._seen_data(d.addr1, d.addr2, False, len(pkt), None)

        sniff(iface=self.mon, prn=handle, store=False, timeout=duration,
              stop_filter=lambda _: self._stop.is_set())
        return True

    def _capture_tcpdump(self, duration: float) -> bool:
        if not shutil.which("tcpdump"):
            return False
        mac = r"([0-9a-f]{2}(?::[0-9a-f]{2}){5})"
        try:
            proc = subprocess.Popen(
                ["tcpdump", "-i", self.mon, "-y", "IEEE802_11_RADIO", "-e", "-n", "-l", "-s", "256"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            )
        except OSError:
            return False
        end = time.time() + duration
        try:
            for line in proc.stdout:  # type: ignore[union-attr]
                if time.time() > end or self._stop.is_set():
                    break
                sig = re.search(r"(-\d+)dBm signal", line)
                rssi = float(sig.group(1)) if sig else None
                beacon = re.search(rf"BSSID:{mac}.*(?:Beacon|Probe Response) \(([^)]*)\)", line)
                if beacon:
                    self._seen_ap(beacon.group(1), beacon.group(2), rssi)
                    continue
                if " Data" not in line:
                    continue
                up = re.search(rf"BSSID:{mac} SA:{mac} DA:{mac}", line)
                down = re.search(rf"DA:{mac} BSSID:{mac} SA:{mac}", line)
                if up:
                    self._seen_data(up.group(2), up.group(1), True, 0, rssi)
                elif down:
                    self._seen_data(down.group(1), down.group(2), False, 0, None)
        finally:
            proc.terminate()
        return True

    def run(self, duration: float, dwell: float = 0.4) -> bool:
        """Capture for ``duration`` seconds while hopping channels."""
        self._stop.clear()
        hopper = threading.Thread(target=self._hop, args=(dwell,), daemon=True)
        hopper.start()
        try:
            ok = self._capture_scapy(duration) or self._capture_tcpdump(duration)
        finally:
            self._stop.set()
            hopper.join(timeout=5)
        return ok

    def stop(self) -> None:
        self._stop.set()

    # -- analysis ----------------------------------------------------------
    def findings(self, oui_lookup: OuiLookup, own_macs: set[str]) -> list[dict]:
        """Classify stations and APs seen over the air."""
        results = []
        for mac, s in self.stations.items():
            if mac in own_macs:
                continue
            mfr, tier = oui_lookup(mac)
            dwell = self.dwell.get(s["channel"]) or 1.0
            if s["up_bytes"]:
                rate = s["up_bytes"] / dwell
                streaming = rate >= 50_000 and s["up_bytes"] >= 3 * max(s["down_bytes"], 1)
                rate_txt = f"{rate * 8 / 1e6:.2f} Mbit/s uplink"
            else:
                rate = s["up_frames"] / dwell
                streaming = rate >= 40 and s["up_frames"] >= 2 * max(s["down_frames"], 1)
                rate_txt = f"{rate:.0f} frames/s uplink"
            close = s["rssi"] is not None and s["rssi"] >= -65
            ssid = self.aps.get(s["bssid"], {}).get("ssid") or s["bssid"]

            if tier in (1, 2) and streaming and close:
                risk, dtype = "CRITICAL", "Camera streaming over the air (other network)"
            elif tier in (1, 2, 3):
                risk, dtype = "HIGH", "Camera-brand device on a nearby network"
            elif streaming and close:
                risk, dtype = "HIGH", "Close device with continuous video-like upload"
            elif streaming:
                risk, dtype = "MODERATE", "Device with continuous video-like upload"
            else:
                continue
            results.append(finding(
                risk, "rf-monitor", mac, mfr or "Unknown", dtype,
                f"Connected to '{ssid}' on channel {s['channel']}; {rate_txt}; "
                f"{proximity(s['rssi'])}",
                f"Use '--locate mon:{mac}' and walk around: signal rises as you get closer.",
            ))
        aps = [{"bssid": b, "ssid": a["ssid"], "channel": str(a["channel"]),
                "signal_dbm": a["rssi"]} for b, a in self.aps.items()]
        results.extend(classify_aps(aps, oui_lookup))
        for r in results:
            r["source"] = r["ip"] = "rf-monitor"
        return results


# ===========================================================================
# Locator
# ===========================================================================

def _bar(dbm: float | None) -> str:
    if dbm is None:
        return "  (no signal)"
    level = max(0, min(40, int((dbm + 95) * 40 / 65)))
    heat = "HOT " if dbm >= -50 else "WARM" if dbm >= -65 else "COLD"
    return f"  {heat} [{'#' * level}{'.' * (40 - level)}] {dbm:.0f} dBm"


def _ping_ms(ip: str) -> float | None:
    if SYSTEM == "Windows":
        cmd = ["ping", "-n", "1", "-w", "1000", ip]
    elif SYSTEM == "Darwin":
        cmd = ["ping", "-c", "1", "-W", "1000", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
    out, _ = _run(cmd, timeout=3)
    m = re.search(r"time[=<]([\d.]+)", out)
    return float(m.group(1)) if m else None


def locate(target: str, iface: str) -> None:
    """Live proximity readout until Ctrl-C.

    target forms: <ip> | wifi:<BSSID> | ble:<address> | mon:<MAC>
    """
    kind, _, value = target.partition(":") if re.match(r"^(wifi|ble|mon):", target) else ("ip", "", target)
    print(f"\n  Locating {value} via {kind}. Walk slowly around the room; Ctrl-C to stop.\n")
    try:
        if kind == "ip":
            print("  Latency is a weak proximity hint; watch for drops and jumps when you shield it.")
            while True:
                ms = _ping_ms(value)
                print(f"  {'no reply' if ms is None else f'{ms:6.1f} ms'}", flush=True)
                time.sleep(1)
        elif kind == "wifi":
            while True:
                hit = [a for a in scan_wifi_aps(iface) if a["bssid"] == value.upper()]
                print(_bar(hit[0]["signal_dbm"] if hit else None), flush=True)
                time.sleep(2)
        elif kind == "ble":
            import asyncio
            from bleak import BleakScanner

            def cb(dev, adv):
                if dev.address.upper() == value.upper():
                    print(_bar(adv.rssi), flush=True)

            async def _watch():
                async with BleakScanner(detection_callback=cb):
                    while True:
                        await asyncio.sleep(1)

            asyncio.run(_watch())
        elif kind == "mon":
            cap = MonitorCapture(iface)
            if not cap.setup():
                return
            cap.target = value.upper()
            last = [0.0]

            def on_target(rssi, ch):
                if time.time() - last[0] >= 0.5:
                    last[0] = time.time()
                    print(f"{_bar(rssi)}  ch{ch}", flush=True)

            cap.on_target = on_target
            try:
                cap.run(duration=24 * 3600)
            finally:
                cap.teardown()
    except KeyboardInterrupt:
        print("\n  Stopped.")
    except ImportError:
        print("  BLE locate needs bleak: pip install bleak")


# ===========================================================================
# Survey: estimate position from readings at several known spots
# ===========================================================================

# Expected RSSI at 1 m and indoor path-loss exponent, per radio type
_PATH_LOSS = {"wifi": (-40.0, 2.7), "mon": (-40.0, 2.7), "ble": (-59.0, 2.2)}


def rssi_to_metres(dbm: float, kind: str) -> float:
    """Log-distance path-loss estimate. Expect +/- a few metres indoors."""
    ref, n = _PATH_LOSS.get(kind, _PATH_LOSS["wifi"])
    return 10 ** ((ref - dbm) / (10 * n))


def _sample(kind: str, value: str, iface: str, seconds: float,
            cap: MonitorCapture | None) -> list[float]:
    samples: list[float] = []
    if kind == "wifi":
        end = time.time() + seconds
        while time.time() < end:
            for a in scan_wifi_aps(iface):
                if a["bssid"] == value.upper() and a["signal_dbm"] is not None:
                    samples.append(a["signal_dbm"])
    elif kind == "ble":
        import asyncio
        from bleak import BleakScanner

        def cb(dev, adv):
            if dev.address.upper() == value.upper():
                samples.append(float(adv.rssi))

        async def _watch():
            async with BleakScanner(detection_callback=cb):
                await asyncio.sleep(seconds)

        asyncio.run(_watch())
    elif kind == "mon" and cap is not None:
        cap.on_target = lambda rssi, ch: rssi is not None and samples.append(rssi)
        cap.run(duration=seconds)
    return samples


def _trilaterate(points: list[tuple[float, float, float]]) -> tuple[float, float]:
    """Grid search for the (x, y) that best fits the distance estimates."""
    xs = [p[0] for p in points]
    ys = [p[1] for p in points]
    best, best_err = (0.0, 0.0), float("inf")
    x = min(xs) - 3
    while x <= max(xs) + 3:
        y = min(ys) - 3
        while y <= max(ys) + 3:
            # Weight near readings more: they are far more reliable
            err = sum((((x - px) ** 2 + (y - py) ** 2) ** 0.5 - d) ** 2 / max(d, 0.5)
                      for px, py, d in points)
            if err < best_err:
                best, best_err = (x, y), err
            y += 0.1
        x += 0.1
    return best


def survey(target: str, iface: str, seconds: float = 8.0) -> None:
    """Interactive multi-spot survey for wifi:/ble:/mon: targets."""
    kind, _, value = target.partition(":")
    if kind not in _PATH_LOSS:
        print("  Survey needs a radio target: wifi:<BSSID>, ble:<address> or mon:<MAC>.")
        print("  For a device on your network, use mon:<its MAC> (monitor mode).")
        return
    print(f"\n  Survey for {value} ({kind}).")
    print("  Stand at a spot, type a label, optionally followed by x,y in metres")
    print("  (e.g. 'door 0,0' or 'bed 3.5,2'). Use 3+ spots spread around the room.")
    print("  Press Enter on an empty line to finish.\n")

    cap = None
    if kind == "mon":
        cap = MonitorCapture(iface)
        if not cap.setup():
            return
        cap.target = value.upper()

    readings: list[dict] = []
    try:
        while True:
            line = input("  spot> ").strip()
            if not line:
                break
            m = re.match(r"^(.*?)\s+(-?[\d.]+)\s*,\s*(-?[\d.]+)$", line)
            label, xy = (m.group(1), (float(m.group(2)), float(m.group(3)))) if m else (line, None)
            print(f"  Measuring for {seconds:.0f}s — hold still...", flush=True)
            samples = _sample(kind, value, iface, seconds, cap)
            if not samples:
                print("  No signal from target here.\n")
                continue
            samples.sort()
            dbm = samples[len(samples) // 2]  # median resists reflections
            dist = rssi_to_metres(dbm, kind)
            readings.append({"label": label, "xy": xy, "dbm": dbm, "m": dist})
            print(f"  {label}: {dbm:.0f} dBm (~{dist:.1f} m, {len(samples)} samples)\n")
    except (KeyboardInterrupt, EOFError):
        print()
    finally:
        if cap:
            cap.teardown()

    if not readings:
        return
    readings.sort(key=lambda r: -r["dbm"])
    print("  --- SURVEY RESULT ---")
    for r in readings:
        print(f"  {r['label']:<20} {r['dbm']:>5.0f} dBm   ~{r['m']:.1f} m")
    print(f"\n  Closest spot: {readings[0]['label']} (~{readings[0]['m']:.1f} m away).")
    placed = [(r["xy"][0], r["xy"][1], r["m"]) for r in readings if r["xy"]]
    if len(placed) >= 3:
        x, y = _trilaterate(placed)
        print(f"  Estimated position: x={x:.1f} m, y={y:.1f} m (same axes you entered).")
    elif placed:
        print("  Give x,y for 3+ spots to get an estimated position.")
    print("  Search within ~1-2 m of that point: smoke detectors, chargers, clocks, vents.\n")
