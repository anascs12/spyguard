#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
ONVIF default-credential audit — test discovered cameras for factory-default
usernames and passwords. Detection-only: reports which cameras are unsecured,
never streams, records, or changes any settings.

Usage:
    python3 onvif_audit.py 192.168.1.100              # single IP
    python3 onvif_audit.py 192.168.1.100 192.168.1.50 # multiple IPs
    python3 onvif_audit.py --from-scan results.json    # from a scan export
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Default credentials database — factory defaults from vendor documentation
# ---------------------------------------------------------------------------
DEFAULT_CREDENTIALS: list[tuple[str, str, str]] = [
    # (username, password, brand/note)
    ("admin", "admin",       "Generic default"),
    ("admin", "",            "Many IP cameras"),
    ("admin", "12345",       "Hikvision older models"),
    ("admin", "123456",      "Dahua older models"),
    ("admin", "password",    "Generic"),
    ("admin", "888888",      "Dahua DVR"),
    ("admin", "1111",        "Samsung"),
    ("admin", "4321",        "Swann"),
    ("admin", "1234",        "Axis (older)"),
    ("admin", "pass",        "Generic"),
    ("admin", "admin1234",   "Reolink"),
    ("root",  "root",        "Axis / Vivotek"),
    ("root",  "pass",        "Vivotek"),
    ("root",  "",            "Some Linux-based cameras"),
    ("root",  "camera",      "AVTECH"),
    ("888888", "888888",     "Dahua DVR"),
    ("666666", "666666",     "Dahua NVR"),
    ("default", "default",   "Amcrest"),
    ("user",  "user",        "Generic"),
    ("admin", "7ujMko0admin","XMEye backdoor"),
    ("admin", "tlJwpbo6",    "XMEye DVR"),
    ("admin", "xmhdipc",     "XMEye IPC"),
    ("admin", "juantech",    "XMEye variant"),
]

# ONVIF service paths
ONVIF_PATHS = [
    "/onvif/device_service",
    "/onvif/media_service",
]

# RTSP paths commonly used by cameras
RTSP_PATHS = [
    "/",
    "/Streaming/Channels/101",
    "/cam/realmonitor?channel=1&subtype=0",
    "/live/ch00_0",
    "/h264_stream",
    "/stream1",
    "/videoMain",
    "/video.h264",
    "/11",
    "/ch0_0.h264",
]


@dataclass
class AuditResult:
    ip: str
    port: int = 80
    protocol: str = ""          # ONVIF, HTTP, RTSP
    username: str = ""
    password: str = ""
    brand_hint: str = ""
    accessible: bool = False
    device_info: str = ""
    timestamp: str = ""


def _run(cmd: list[str], timeout: int = 10) -> tuple[str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr, r.returncode
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return "", -1


# ---------------------------------------------------------------------------
# ONVIF SOAP probe
# ---------------------------------------------------------------------------

def _onvif_get_device_info(ip: str, port: int, user: str, passwd: str) -> str | None:
    """Try ONVIF GetDeviceInformation with given credentials. Returns device info or None."""
    # Build WS-Security UsernameToken
    nonce_raw = hashlib.sha256(f"{time.time()}{user}".encode()).digest()[:16]
    import base64
    nonce_b64 = base64.b64encode(nonce_raw).decode()
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Password digest: Base64(SHA1(nonce + created + password))
    digest_input = nonce_raw + created.encode() + passwd.encode()
    password_digest = base64.b64encode(hashlib.sha1(digest_input).digest()).decode()

    soap = f"""<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
            xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
            xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
  <s:Header>
    <wsse:Security>
      <wsse:UsernameToken>
        <wsse:Username>{user}</wsse:Username>
        <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest">{password_digest}</wsse:Password>
        <wsse:Nonce EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary">{nonce_b64}</wsse:Nonce>
        <wsu:Created>{created}</wsu:Created>
      </wsse:UsernameToken>
    </wsse:Security>
  </s:Header>
  <s:Body>
    <tds:GetDeviceInformation/>
  </s:Body>
</s:Envelope>"""

    proto = "https" if port in (443, 8443) else "http"
    url = f"{proto}://{ip}:{port}/onvif/device_service"

    curl_cmd = [
        "curl", "-s", "-m", "8", "-k",
        "-H", "Content-Type: application/soap+xml; charset=utf-8",
        "-d", soap, url,
    ]

    out, rc = _run(curl_cmd, timeout=12)
    if rc != 0:
        return None

    # Check for successful response (contains Manufacturer/Model)
    if "Manufacturer" in out or "FirmwareVersion" in out:
        mfg = ""
        model = ""
        m = re.search(r"<.*?Manufacturer>([^<]+)", out)
        if m:
            mfg = m.group(1)
        m = re.search(r"<.*?Model>([^<]+)", out)
        if m:
            model = m.group(1)
        return f"{mfg} {model}".strip() or "Unknown ONVIF device"

    # Check for auth failure
    if "NotAuthorized" in out or "401" in out or "Sender" in out:
        return None

    return None


# ---------------------------------------------------------------------------
# HTTP basic auth probe
# ---------------------------------------------------------------------------

def _http_auth_check(ip: str, port: int, user: str, passwd: str) -> str | None:
    """Try HTTP basic auth. Returns page title or None."""
    proto = "https" if port in (443, 8443) else "http"
    url = f"{proto}://{ip}:{port}/"

    out, rc = _run([
        "curl", "-s", "-m", "5", "-k",
        "-u", f"{user}:{passwd}",
        "-w", "\n%{http_code}", url,
    ], timeout=8)

    lines = out.strip().rsplit("\n", 1)
    if len(lines) < 2:
        return None

    body, status = lines[0], lines[1]
    if status.startswith("2"):
        m = re.search(r"<title>([^<]+)</title>", body, re.IGNORECASE)
        title = m.group(1).strip() if m else "Web interface"
        return title

    return None


# ---------------------------------------------------------------------------
# RTSP auth probe
# ---------------------------------------------------------------------------

def _rtsp_auth_check(ip: str, port: int, user: str, passwd: str) -> str | None:
    """Try RTSP DESCRIBE with credentials. Returns stream info or None."""
    if not shutil.which("curl"):
        return None

    for path in RTSP_PATHS[:3]:
        url = f"rtsp://{user}:{passwd}@{ip}:{port}{path}"
        out, rc = _run(["curl", "-s", "-m", "5", "-I", url], timeout=8)
        if "200 OK" in out or "RTSP/1.0 200" in out:
            return f"RTSP stream at {path}"

    return None


# ---------------------------------------------------------------------------
# Audit a single target
# ---------------------------------------------------------------------------

def audit_target(ip: str, ports: list[int] | None = None) -> list[AuditResult]:
    """Test a target IP against default credentials. Returns findings."""
    results: list[AuditResult] = []
    if ports is None:
        ports = [80, 8080, 443, 554, 8554, 8899]

    ts = datetime.now(timezone.utc).isoformat()

    for port in ports:
        for user, passwd, brand in DEFAULT_CREDENTIALS:
            # ONVIF check (HTTP ports)
            if port not in (554, 8554):
                info = _onvif_get_device_info(ip, port, user, passwd)
                if info:
                    results.append(AuditResult(
                        ip=ip, port=port, protocol="ONVIF",
                        username=user, password="***" if passwd else "(empty)",
                        brand_hint=brand, accessible=True,
                        device_info=info, timestamp=ts,
                    ))
                    return results

            # HTTP check (non-RTSP ports)
            if port not in (554, 8554):
                title = _http_auth_check(ip, port, user, passwd)
                if title:
                    results.append(AuditResult(
                        ip=ip, port=port, protocol="HTTP",
                        username=user, password="***" if passwd else "(empty)",
                        brand_hint=brand, accessible=True,
                        device_info=title, timestamp=ts,
                    ))
                    return results

            # RTSP check
            if port in (554, 8554):
                stream = _rtsp_auth_check(ip, port, user, passwd)
                if stream:
                    results.append(AuditResult(
                        ip=ip, port=port, protocol="RTSP",
                        username=user, password="***" if passwd else "(empty)",
                        brand_hint=brand, accessible=True,
                        device_info=stream, timestamp=ts,
                    ))
                    return results

    return results


# ---------------------------------------------------------------------------
# Batch audit from scan results
# ---------------------------------------------------------------------------

def audit_from_scan(scan_json_path: str) -> list[AuditResult]:
    """Load a scan JSON export and audit all HIGH+ devices."""
    import json
    with open(scan_json_path) as f:
        data = json.load(f)

    results: list[AuditResult] = []
    devices = data if isinstance(data, list) else data.get("devices", [])

    for dev in devices:
        risk = dev.get("risk", "INFO")
        if risk not in ("CRITICAL", "HIGH"):
            continue
        ip = dev.get("ip", "")
        if not ip:
            continue
        ports = [int(p) for p in dev.get("ports", "").split(",") if p.strip().isdigit()]
        if not ports:
            ports = None
        results.extend(audit_target(ip, ports))

    return results


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="ONVIF default-credential audit (detection-only)",
    )
    parser.add_argument("targets", nargs="*", help="IP addresses to audit")
    parser.add_argument("--from-scan", help="Load targets from a scan JSON export")
    parser.add_argument("--ports", default="80,8080,554",
                        help="Ports to check (comma-separated)")
    args = parser.parse_args()

    if not args.targets and not args.from_scan:
        parser.print_help()
        return

    print(f"\n  ONVIF Default-Credential Audit")
    print(f"  {'=' * 40}")
    print(f"  Detection-only: never streams or changes settings.\n")

    all_results: list[AuditResult] = []

    if args.from_scan:
        print(f"  Loading targets from {args.from_scan}...")
        all_results = audit_from_scan(args.from_scan)
    else:
        ports = [int(p) for p in args.ports.split(",")]
        for ip in args.targets:
            print(f"  Testing {ip}...", end=" ", flush=True)
            results = audit_target(ip, ports)
            if results:
                print(f"⚠️  DEFAULT CREDENTIALS FOUND")
            else:
                print("✓ secured")
            all_results.extend(results)

    print()
    if all_results:
        print(f"  ⚠️  {len(all_results)} camera(s) with default credentials:\n")
        for r in all_results:
            masked_pw = r.password if r.password in ("(empty)", "***") else "***"
            print(f"    {r.ip}:{r.port} ({r.protocol})")
            print(f"      Credentials: {r.username} / {masked_pw} ({r.brand_hint})")
            print(f"      Device: {r.device_info}")
            print(f"      Action: Change the password immediately.")
            print()
    else:
        print("  ✓ No cameras with default credentials found.\n")


if __name__ == "__main__":
    main()
