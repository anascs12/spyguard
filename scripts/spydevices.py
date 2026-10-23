#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Known spy-device database.

Curated catalogue of hidden/covert camera hardware: MAC OUI prefixes,
default ports, mDNS service names, UPnP device types, HTTP fingerprints,
and P2P cloud relay identifiers.  These produce HIGH-confidence matches
that bypass the heuristic scoring in phase6_classify.

Categories:
  SPY_COVERT    — devices marketed as hidden/spy cameras (clock, charger, etc.)
  SPY_PINHOLE   — pinhole / button / screw camera modules
  P2P_CLOUD     — P2P relay protocols used by cheap Chinese cameras
  CONSUMER_CAM  — mass-market consumer cameras often placed covertly
"""

from __future__ import annotations

import re

# ───────────────────────────────────────────────────────────────────────
# P2P cloud relay protocols — these are the server-side relay services
# that cheap spy cameras phone home to.  A device connecting to one of
# these on the LAN is almost certainly a camera.
# ───────────────────────────────────────────────────────────────────────

P2P_PORTS = {
    32100,   # Tutk/IOTC (XMEye, CamHi, V380, HiSilicon family)
    34567,   # XMEye/NETSurveillance proprietary
    34599,   # XMEye secondary
    9527,    # HiSilicon telnet/debug
    8899,    # V380 HTTP control
    6789,    # Unitech/Sricam P2P
    32108,   # PPPP (Shenzhen Yunni, iCSee)
    20188,   # Tuya camera P2P
}

P2P_DOMAINS = [
    # These are cloud relay servers; outbound DNS to any of them from a
    # LAN device is strong evidence of a P2P camera.
    r"\.tutk\.com$",
    r"\.p2p\.eye4\.cn$",
    r"\.ipc2p\.net$",
    r"\.xmcsrv\.net$",
    r"\.secu100\.net$",
    r"\.csdev\.net$",
    r"\.cloudlinks\.cn$",
    r"\.eseecloud\.com$",
    r"\.hik-connect\.com$",
    r"\.ezvizlife\.com$",
    r"\.iotcplatform\.com$",
    r"\.ppstream\.com$",
    r"\.camera\.meari\.com\.cn$",
    r"\.sricctv\.com$",
    r"\.danale\.com$",
    r"p2p-duid-cn\.cloudlinks\.cn$",
]
P2P_DOMAIN_RE = re.compile("|".join(P2P_DOMAINS), re.IGNORECASE)

# ───────────────────────────────────────────────────────────────────────
# Known spy-camera OUI prefixes (6-char uppercase hex, no separators).
# These supplement the broader TIER1/TIER2 lists in scan.py with
# prefixes specific to known covert/spy devices.
# ───────────────────────────────────────────────────────────────────────

SPY_OUIS: dict[str, str] = {
    # V380 / V380 Pro family (HiSilicon SoC, sold on AliExpress as "spy camera")
    "A03E6B": "V380",
    "E8AB20": "V380",
    "507BF5": "V380",
    # XMEye / NETSurveillance family
    "005043": "XMEye/NETSurveillance",
    "001272": "XMEye/NETSurveillance",
    "4C11BF": "XMEye/Dahua-OEM",
    # iCSee / Shenzhen Yunni
    "5C6267": "iCSee/Yunni",
    "34EA34": "iCSee/Yunni",
    # CamHi family
    "4C57CA": "CamHi",
    "1CBFCE": "CamHi",
    # Wansview
    "7C2E10": "Wansview",
    # HiSilicon generic camera modules
    "587A62": "HiSilicon-IPC",
    "00107B": "HiSilicon-IPC",
    # Sricam / Sricctv
    "C0A5DD": "Sricam",
    # ESP32-CAM modules (very common in DIY spy cameras)
    "30AEA4": "Espressif-CAM",
    "24A160": "Espressif-CAM",
    "B4E62D": "Espressif-CAM",
    "240AC4": "Espressif-CAM",
    "8CAAB5": "Espressif-CAM",
    "3CE090": "Espressif-CAM",
    "A4CF12": "Espressif-CAM",
    "FCAB90": "Espressif-CAM",
    # Tuya camera modules
    "D8F15B": "Tuya-CAM",
    "10D561": "Tuya-CAM",
    "847127": "Tuya-CAM",
    # Wyzecam
    "2CAA8E": "Wyze",
    "7C78B2": "Wyze",
    # Xiaovv / Xiaomi ecosystem spy-style cams
    "64B80C": "Xiaovv",
    # ESCAM / QF-series pinhole cameras
    "DC4E8F": "ESCAM",
    # Anbiux / Hiseeu
    "CC7A1D": "Anbiux/Hiseeu",
    # Vstarcam
    "000D81": "Vstarcam",
    "1C1BBD": "Vstarcam",
}

# ───────────────────────────────────────────────────────────────────────
# Model-string patterns matched against HTTP title, Server header,
# ONVIF device model, and mDNS hostname.  These identify specific spy
# camera products (not just brands).
# ───────────────────────────────────────────────────────────────────────

SPY_MODEL_PATTERNS = re.compile(
    r"(?i)"
    r"V380|V380\s*Pro|"
    r"XMEye|NETSurveillance|XM\s*camera|"
    r"iCSee|Eye4|EseeCloud|"
    r"CamHi|HiP2P|"
    r"HDWIFICAM|HDWifiCamPro|"
    r"Wansview|"
    r"YI\s*Home|YI\s*Dome|"
    r"Vstarcam|VstarCam|"
    r"Sricam|SriHome|"
    r"ESCAM|"
    r"LeFun|"
    r"TENVIS|"
    r"Anbiux|Hiseeu|"
    r"JOOAN|ZOSI|SANNCE|"
    r"Xiaovv|"
    r"Wyzecam|WyzeCam|"
    r"Reolink\s*Go|"
    r"ESP32.?CAM|"
    r"JAWS/|Boa/0|GoAhead.Webs|GoAhead|"
    r"uc-httpd|DNVRS-Webs|App-webs|"
    r"mini\s*camera|spy\s*camera|hidden\s*camera|"
    r"pinhole|button\s*cam|nanny\s*cam|clock\s*cam|"
    r"charger\s*cam|smoke\s*detector\s*cam|"
    r"pen\s*cam|glasses\s*cam|teddy\s*cam"
)

# HTTP server headers that indicate a spy-camera firmware
SPY_HTTP_SERVERS = re.compile(
    r"(?i)^(?:GoAhead-Webs|JAWS/1|Boa/0|uc-httpd|DNVRS-Webs|App-webs|mini_httpd/1)",
)

# ───────────────────────────────────────────────────────────────────────
# Default camera ports per product family.  The scanner already tests
# CAMERA_PORTS; these let us raise confidence when a known spy device
# port combination is found on a single host.
# ───────────────────────────────────────────────────────────────────────

SPY_PORT_COMBOS: list[tuple[set[int], str]] = [
    ({34567, 34599},    "XMEye/NETSurveillance (dual control ports)"),
    ({32100, 80},       "Tutk P2P camera (IOTC + HTTP)"),
    ({9527, 80},        "HiSilicon debug + HTTP (common spy-cam module)"),
    ({8899, 80},        "V380 control + HTTP"),
    ({554, 8899},       "V380 RTSP + control"),
    ({32108, 80},       "PPPP P2P relay + HTTP (iCSee family)"),
    ({20188, 6668},     "Tuya camera P2P + media"),
    ({6789, 80},        "Sricam P2P + HTTP"),
]

# ───────────────────────────────────────────────────────────────────────
# Continuous-upload detection.  Cameras stream video 24/7 to a cloud
# relay or NVR.  A device that sustains > UPLOAD_THRESHOLD_BPS outbound
# traffic (upstream from the LAN's perspective) for > UPLOAD_WINDOW_SEC
# is flagged.
# ───────────────────────────────────────────────────────────────────────

UPLOAD_THRESHOLD_BPS = 100_000   # 100 KB/s — low-res H.264 is ~150–300 KB/s
UPLOAD_WINDOW_SEC = 30           # must sustain for 30 s to distinguish from bursts
VIDEO_STREAMING_PORTS = {1935, 6667, 6668, 8000, 8554, 554, 32100, 34567, 8899, 20188}

# ───────────────────────────────────────────────────────────────────────
# Public helpers
# ───────────────────────────────────────────────────────────────────────

def match_spy_oui(mac: str) -> str | None:
    """Return the spy-device brand if the MAC's OUI is a known spy device, else None."""
    oui = mac.upper().replace(":", "").replace("-", "").replace(".", "")[:6]
    return SPY_OUIS.get(oui)


def match_spy_model(text: str) -> bool:
    """True if the text (HTTP title, server header, hostname) matches a known spy model."""
    return bool(SPY_MODEL_PATTERNS.search(text))


def match_spy_http_server(server: str) -> bool:
    """True if the HTTP Server header is a known spy-camera firmware."""
    return bool(SPY_HTTP_SERVERS.match(server))


def match_p2p_domain(domain: str) -> bool:
    """True if the domain is a known P2P camera cloud relay."""
    return bool(P2P_DOMAIN_RE.search(domain))


def match_spy_port_combo(open_ports: set[int]) -> str | None:
    """Return a description if the host's open ports match a known spy-device combo."""
    for combo, desc in SPY_PORT_COMBOS:
        if combo.issubset(open_ports):
            return desc
    return None


def is_p2p_port(port: int) -> bool:
    """True if the port is a known P2P camera relay port."""
    return port in P2P_PORTS


def is_video_streaming_port(port: int) -> bool:
    """True if the port is typically used for continuous video upload."""
    return port in VIDEO_STREAMING_PORTS
