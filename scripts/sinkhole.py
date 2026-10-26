#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
DNS sinkhole mode — block spy-camera cloud uploads by redirecting known P2P
camera domains to 127.0.0.1 in /etc/hosts.

While active, cameras on the local network cannot phone home to their cloud
relay servers, blocking live streaming and recordings from leaving the premises.

Usage:
    sudo python3 sinkhole.py --enable      # block camera cloud domains
    sudo python3 sinkhole.py --disable     # restore /etc/hosts
    sudo python3 sinkhole.py --status      # show current state
    sudo python3 sinkhole.py --list        # list blocked domains
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import sys
import time
from pathlib import Path

try:
    import spydevices
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import spydevices

SYSTEM = platform.system()
HOSTS_PATH = Path("C:/Windows/System32/drivers/etc/hosts") if SYSTEM == "Windows" else Path("/etc/hosts")
MARKER_BEGIN = "# >>> SpyGuard sinkhole — do not edit this block"
MARKER_END   = "# <<< SpyGuard sinkhole"
BACKUP_SUFFIX = ".spyguard-backup"

# Extended domain list: P2P camera relay + cloud upload + OTA update servers
SINKHOLE_DOMAINS: list[str] = [
    *spydevices.P2P_DOMAINS,
    # Additional camera cloud endpoints
    "m2m.tutk.com",
    "log.tutk.com",
    "api.tutk.com",
    "p2p1.tutk.com",
    "p2p2.tutk.com",
    "push.tutk.com",
    "dss.xiongmaitech.com",
    "upgrade.xiongmaitech.com",
    "uid.xiongmaitech.com",
    "cloud.v380.net",
    "push.v380.net",
    "www.v380.net",
    "api.v380.net",
    "cloud.eye4.cn",
    "api.eye4.cn",
    "log.eye4.cn",
    "p2p.cloudlinks.cn",
    "api.hik-connect.com",
    "liteapi.hik-connect.com",
    "spcld.smartlife.tn",
    "a2.tuyacn.com",
    "a2.tuyaus.com",
    "a2.tuyaeu.com",
    "mqtt.tuyacn.com",
    "mqtt.tuyaus.com",
    "mqtt.tuyaeu.com",
    "m1.tuyacn.com",
    "m1.tuyaus.com",
    "m1.tuyaeu.com",
    "iot.tuya.com",
    "api.vstarcam.com",
    "cloud.vstarcam.com",
    "api.yoosee.co",
    "p2p.yoosee.co",
    "cloud.yoosee.co",
    "cloud.camhi.com",
    "p2p.camhi.com",
    "api.eseecloud.com",
    "p2p.eseecloud.com",
    "p2p.wansview.com",
    "cloud.tenvis.com",
]


def _read_hosts() -> str:
    try:
        return HOSTS_PATH.read_text()
    except PermissionError:
        print("  Error: need root/admin to read hosts file.")
        sys.exit(1)


def _write_hosts(content: str) -> None:
    try:
        HOSTS_PATH.write_text(content)
    except PermissionError:
        print("  Error: need root/admin to write hosts file.")
        sys.exit(1)


def _flush_dns() -> None:
    """Flush DNS cache so sinkhole takes effect immediately."""
    if SYSTEM == "Linux":
        if shutil.which("systemd-resolve"):
            os.system("systemd-resolve --flush-caches 2>/dev/null")
        elif shutil.which("resolvectl"):
            os.system("resolvectl flush-caches 2>/dev/null")
    elif SYSTEM == "Darwin":
        os.system("dscacheutil -flushcache 2>/dev/null")
        os.system("sudo killall -HUP mDNSResponder 2>/dev/null")
    elif SYSTEM == "Windows":
        os.system("ipconfig /flushdns >nul 2>&1")


def is_enabled() -> bool:
    """Check if the sinkhole is currently active."""
    return MARKER_BEGIN in _read_hosts()


def get_blocked_domains() -> list[str]:
    """Return list of currently blocked domains."""
    content = _read_hosts()
    if MARKER_BEGIN not in content:
        return []

    domains = []
    in_block = False
    for line in content.splitlines():
        if line.strip() == MARKER_BEGIN:
            in_block = True
            continue
        if line.strip() == MARKER_END:
            break
        if in_block and line.strip() and not line.startswith("#"):
            parts = line.split()
            if len(parts) >= 2:
                domains.append(parts[1])
    return domains


def enable(extra_domains: list[str] | None = None) -> int:
    """Enable the DNS sinkhole. Returns number of domains blocked."""
    if is_enabled():
        print("  Sinkhole is already active. Use --disable first to update.")
        return 0

    # Deduplicate, and keep only valid hostnames. SINKHOLE_DOMAINS pulls in
    # spydevices.P2P_DOMAINS, which are regex patterns (e.g. r"\.tutk\.com$"):
    # writing those to /etc/hosts makes systemd-resolved log a parse error that
    # the traffic detector then misreads as a camera. Drop anything that isn't
    # a plain hostname.
    valid_host = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", re.IGNORECASE)
    all_domains = sorted({d for d in set(SINKHOLE_DOMAINS + (extra_domains or [])) if valid_host.match(d)})

    # Backup
    content = _read_hosts()
    backup_path = str(HOSTS_PATH) + BACKUP_SUFFIX
    if not os.path.exists(backup_path):
        Path(backup_path).write_text(content)

    # Build sinkhole block
    block_lines = [MARKER_BEGIN]
    for domain in all_domains:
        block_lines.append(f"127.0.0.1  {domain}")
    block_lines.append(MARKER_END)

    new_content = content.rstrip("\n") + "\n\n" + "\n".join(block_lines) + "\n"
    _write_hosts(new_content)
    _flush_dns()

    return len(all_domains)


def disable() -> bool:
    """Disable the DNS sinkhole. Returns True if it was active."""
    content = _read_hosts()
    if MARKER_BEGIN not in content:
        return False

    # Remove the sinkhole block
    lines = content.splitlines()
    new_lines = []
    in_block = False
    for line in lines:
        if line.strip() == MARKER_BEGIN:
            in_block = True
            continue
        if line.strip() == MARKER_END:
            in_block = False
            continue
        if not in_block:
            new_lines.append(line)

    # Clean up trailing blank lines
    while new_lines and not new_lines[-1].strip():
        new_lines.pop()
    new_lines.append("")

    _write_hosts("\n".join(new_lines))
    _flush_dns()

    # Remove backup
    backup_path = str(HOSTS_PATH) + BACKUP_SUFFIX
    if os.path.exists(backup_path):
        try:
            os.unlink(backup_path)
        except OSError:
            pass

    return True


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="DNS sinkhole — block spy-camera cloud uploads",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--enable", action="store_true", help="Activate sinkhole")
    group.add_argument("--disable", action="store_true", help="Deactivate sinkhole")
    group.add_argument("--status", action="store_true", help="Show current state")
    group.add_argument("--list", action="store_true", help="List blocked domains")
    parser.add_argument("--extra", nargs="*", help="Additional domains to block")
    args = parser.parse_args()

    print(f"\n  DNS Sinkhole")
    print(f"  {'=' * 40}")

    if args.status:
        if is_enabled():
            domains = get_blocked_domains()
            print(f"  Status: ACTIVE — {len(domains)} domains blocked")
            print(f"  Cameras on this network cannot upload to cloud relays.")
        else:
            print(f"  Status: INACTIVE")
            print(f"  Camera cloud connections are not blocked.")

    elif args.list:
        if is_enabled():
            domains = get_blocked_domains()
            print(f"  {len(domains)} domains blocked:\n")
            for d in domains:
                print(f"    → {d}")
        else:
            print(f"  Sinkhole is inactive. No domains blocked.")
            print(f"\n  Available domains ({len(SINKHOLE_DOMAINS)}):\n")
            for d in sorted(SINKHOLE_DOMAINS)[:20]:
                print(f"    {d}")
            if len(SINKHOLE_DOMAINS) > 20:
                print(f"    ... and {len(SINKHOLE_DOMAINS) - 20} more")

    elif args.enable:
        count = enable(args.extra)
        if count:
            print(f"  ✓ Sinkhole ENABLED — {count} camera cloud domains blocked")
            print(f"  Cameras cannot upload to cloud relays while active.")
            print(f"  Run with --disable to restore normal DNS resolution.")
        else:
            print(f"  Already active.")

    elif args.disable:
        was_active = disable()
        if was_active:
            print(f"  ✓ Sinkhole DISABLED — /etc/hosts restored")
            print(f"  Camera cloud connections are no longer blocked.")
        else:
            print(f"  Sinkhole was not active.")

    print()


if __name__ == "__main__":
    main()
