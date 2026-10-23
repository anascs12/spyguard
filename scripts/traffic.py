#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Network traffic anomaly detection.

Passively watches LAN traffic (via conntrack or tcpdump) to find devices
that are:
  1. Making outbound connections to known P2P camera cloud relays
  2. Sustaining high upstream bandwidth (continuous video upload)
  3. Connecting to known camera streaming ports on the WAN

Detection-only: no traffic is injected, no devices are disconnected,
no packets are modified.  Requires root/capabilities for packet capture.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

import spydevices


@dataclass
class TrafficAnomaly:
    ip: str
    mac: str
    anomaly_type: str   # "p2p_relay", "sustained_upload", "camera_port_wan"
    detail: str
    bytes_out: int = 0
    duration: float = 0.0
    destinations: list[str] = field(default_factory=list)


def _run(cmd: list[str], timeout: int = 10) -> str:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _arp_table() -> dict[str, str]:
    """ip -> mac from the system ARP table."""
    out = _run(["ip", "neigh", "show"])
    table: dict[str, str] = {}
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 5 and "lladdr" in parts:
            idx = parts.index("lladdr")
            if idx + 1 < len(parts):
                table[parts[0]] = parts[idx + 1].upper()
    return table


# ───────────────────────────────────────────────────────────────────────
# Method 1: DNS-based detection (lightest — no raw capture needed)
# ───────────────────────────────────────────────────────────────────────

def check_dns_cache(gateway: str) -> list[TrafficAnomaly]:
    """Check the system's DNS cache for queries to known P2P camera domains."""
    anomalies: list[TrafficAnomaly] = []
    # systemd-resolved
    out = _run(["resolvectl", "statistics"], timeout=5)
    out2 = _run(["journalctl", "-u", "systemd-resolved", "-n", "500",
                 "--no-pager", "-q"], timeout=10)
    for domain_re in spydevices.P2P_DOMAINS:
        pattern = domain_re.replace(r"\.", ".").strip("$^")
        for line in out2.splitlines():
            if re.search(pattern, line, re.IGNORECASE):
                m = re.search(r"(\S+\.\S+)", line)
                if m:
                    anomalies.append(TrafficAnomaly(
                        ip="", mac="", anomaly_type="p2p_relay",
                        detail=f"DNS query to P2P camera relay: {m.group(1)}",
                        destinations=[m.group(1)],
                    ))
    return anomalies


# ───────────────────────────────────────────────────────────────────────
# Method 2: conntrack-based (works on Linux routers / NAT gateways)
# ───────────────────────────────────────────────────────────────────────

def check_conntrack() -> list[TrafficAnomaly]:
    """Parse conntrack for connections to known camera ports/relays."""
    if not shutil.which("conntrack"):
        return []
    out = _run(["conntrack", "-L", "-o", "extended"], timeout=15)
    anomalies: list[TrafficAnomaly] = []
    arp = _arp_table()

    for line in out.splitlines():
        m = re.search(r"src=(\d+\.\d+\.\d+\.\d+)\s+dst=(\d+\.\d+\.\d+\.\d+).*dport=(\d+)", line)
        if not m:
            continue
        src, dst, dport = m.group(1), m.group(2), int(m.group(3))
        if spydevices.is_p2p_port(dport):
            mac = arp.get(src, "")
            anomalies.append(TrafficAnomaly(
                ip=src, mac=mac, anomaly_type="p2p_relay",
                detail=f"Outbound connection to {dst}:{dport} (P2P camera relay port)",
                destinations=[f"{dst}:{dport}"],
            ))
        elif spydevices.is_video_streaming_port(dport) and _is_wan(dst):
            mac = arp.get(src, "")
            anomalies.append(TrafficAnomaly(
                ip=src, mac=mac, anomaly_type="camera_port_wan",
                detail=f"Outbound video-stream port {dport} to WAN ({dst})",
                destinations=[f"{dst}:{dport}"],
            ))

    return anomalies


def _is_wan(ip: str) -> bool:
    """True if the IP is not RFC1918/link-local."""
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    a, b = int(parts[0]), int(parts[1])
    if a == 10:
        return False
    if a == 172 and 16 <= b <= 31:
        return False
    if a == 192 and b == 168:
        return False
    if a == 169 and b == 254:
        return False
    if a == 127:
        return False
    return True


# ───────────────────────────────────────────────────────────────────────
# Method 3: tcpdump bandwidth monitor (needs raw capture permission)
# ───────────────────────────────────────────────────────────────────────

def monitor_upload_bandwidth(
    interface: str,
    subnet: str,
    duration: int = 30,
    on_anomaly: Callable[[TrafficAnomaly], None] | None = None,
) -> list[TrafficAnomaly]:
    """Watch traffic for devices sustaining high upload (possible camera stream)."""
    if not shutil.which("tcpdump"):
        return []

    ip_bytes: dict[str, int] = {}
    anomalies: list[TrafficAnomaly] = []
    arp = _arp_table()
    stop = threading.Event()

    def capture():
        try:
            proc = subprocess.Popen(
                ["tcpdump", "-i", interface, "-n", "-q", "-l",
                 f"src net {subnet}", "and", "not", f"dst net {subnet}"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
            )
            while not stop.is_set() and proc.poll() is None:
                line = proc.stdout.readline()
                if not line:
                    break
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\.\d+\s*>.*length\s+(\d+)", line)
                if m:
                    ip, size = m.group(1), int(m.group(2))
                    ip_bytes[ip] = ip_bytes.get(ip, 0) + size
            proc.terminate()
        except OSError:
            pass

    t = threading.Thread(target=capture, daemon=True)
    t.start()
    time.sleep(duration)
    stop.set()
    t.join(timeout=5)

    threshold = spydevices.UPLOAD_THRESHOLD_BPS * duration
    for ip, total in ip_bytes.items():
        if total >= threshold:
            rate_kbps = total / duration / 1024
            mac = arp.get(ip, "")
            a = TrafficAnomaly(
                ip=ip, mac=mac, anomaly_type="sustained_upload",
                detail=f"Sustained {rate_kbps:.0f} KB/s upload for {duration}s "
                       f"({total / 1024:.0f} KB total) — consistent with video streaming",
                bytes_out=total, duration=float(duration),
            )
            anomalies.append(a)
            if on_anomaly:
                on_anomaly(a)

    return anomalies


# ───────────────────────────────────────────────────────────────────────
# Combined scan
# ───────────────────────────────────────────────────────────────────────

def scan_traffic(
    interface: str,
    subnet: str,
    gateway: str,
    duration: int = 30,
    deep: bool = False,
) -> list[TrafficAnomaly]:
    """Run all available traffic anomaly checks."""
    results: list[TrafficAnomaly] = []
    results.extend(check_conntrack())
    results.extend(check_dns_cache(gateway))
    if deep:
        results.extend(monitor_upload_bandwidth(interface, subnet, duration))
    # Deduplicate by (ip, anomaly_type)
    seen: set[tuple[str, str]] = set()
    unique: list[TrafficAnomaly] = []
    for a in results:
        key = (a.ip, a.anomaly_type)
        if key not in seen:
            seen.add(key)
            unique.append(a)
    return unique
