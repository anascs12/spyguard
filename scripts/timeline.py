#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Device timeline — track when devices appear and disappear over hours/days.

Repeated scans build a timeline showing each device's presence windows. A camera
that only appears at certain hours (e.g., only at night) is more suspicious than
one that's always on (likely a router).

Usage:
    sudo python3 timeline.py --record           # save a snapshot now
    sudo python3 timeline.py --show             # display timeline
    sudo python3 timeline.py --watch 15         # auto-record every 15 min
    sudo python3 timeline.py --suspicious       # show devices with unusual patterns
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

TIMELINE_DIR = Path("./privacy-scan-results/timeline")
TIMELINE_FILE = TIMELINE_DIR / "device_timeline.json"


def _ensure_dir() -> None:
    TIMELINE_DIR.mkdir(parents=True, exist_ok=True)


def _load_timeline() -> dict:
    """Load existing timeline data."""
    if TIMELINE_FILE.exists():
        try:
            return json.loads(TIMELINE_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {"devices": {}, "snapshots": []}


def _save_timeline(data: dict) -> None:
    _ensure_dir()
    TIMELINE_FILE.write_text(json.dumps(data, indent=2))


def _run_scan() -> list[dict]:
    """Run a quick scan and return discovered devices."""
    script_dir = Path(__file__).resolve().parent
    scan_script = script_dir / "scan.py"

    if not scan_script.exists():
        return []

    try:
        result = subprocess.run(
            [sys.executable, str(scan_script), "--quick", "--no-html", "--lang", "en"],
            capture_output=True, text=True, timeout=120,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    # Parse scan output for device lines
    devices = []
    # Also check for saved JSON
    import glob
    json_files = sorted(glob.glob("./privacy-scan-results/privacy-scan-*.json"))
    if json_files:
        try:
            with open(json_files[-1]) as f:
                scan_data = json.load(f)
            if isinstance(scan_data, list):
                return scan_data
            return scan_data.get("devices", [])
        except (json.JSONDecodeError, OSError):
            pass

    return devices


def record_snapshot(devices: list[dict] | None = None) -> dict:
    """Record a device presence snapshot."""
    if devices is None:
        devices = _run_scan()

    now = datetime.now(timezone.utc).isoformat()
    timeline = _load_timeline()

    snapshot = {
        "timestamp": now,
        "device_count": len(devices),
        "device_ids": [],
    }

    for dev in devices:
        mac = dev.get("mac", dev.get("address", dev.get("id", "")))
        ip = dev.get("ip", "")
        risk = dev.get("risk", "INFO")
        name = dev.get("manufacturer", dev.get("title", "Unknown"))

        if not mac:
            continue

        device_id = mac.upper()
        snapshot["device_ids"].append(device_id)

        if device_id not in timeline["devices"]:
            timeline["devices"][device_id] = {
                "mac": mac,
                "ip": ip,
                "name": name,
                "risk": risk,
                "first_seen": now,
                "last_seen": now,
                "seen_count": 0,
                "windows": [],
            }

        entry = timeline["devices"][device_id]
        entry["last_seen"] = now
        entry["seen_count"] += 1
        if ip:
            entry["ip"] = ip

        # Track presence windows (consecutive sightings)
        windows = entry["windows"]
        if windows and _within_window(windows[-1]["end"], now, margin_minutes=30):
            windows[-1]["end"] = now
            windows[-1]["count"] += 1
        else:
            windows.append({"start": now, "end": now, "count": 1})

    timeline["snapshots"].append(snapshot)
    _save_timeline(timeline)
    return snapshot


def _within_window(last_time: str, current_time: str, margin_minutes: int = 30) -> bool:
    """Check if current_time is within margin of last_time."""
    try:
        last = datetime.fromisoformat(last_time.replace("Z", "+00:00"))
        current = datetime.fromisoformat(current_time.replace("Z", "+00:00"))
        return (current - last).total_seconds() < margin_minutes * 60
    except (ValueError, TypeError):
        return False


def analyze_suspicious() -> list[dict]:
    """Find devices with suspicious presence patterns."""
    timeline = _load_timeline()
    suspicious = []

    for device_id, entry in timeline["devices"].items():
        reasons = []

        # Device seen in only some snapshots (intermittent)
        total_snapshots = len(timeline["snapshots"])
        if total_snapshots >= 3:
            presence_ratio = entry["seen_count"] / total_snapshots
            if 0.1 < presence_ratio < 0.7:
                reasons.append(f"Intermittent: present in {entry['seen_count']}/{total_snapshots} scans ({presence_ratio:.0%})")

        # Device with multiple separate windows (turns on/off)
        if len(entry["windows"]) >= 3:
            reasons.append(f"Turns on/off: {len(entry['windows'])} separate presence windows")

        # Device that appeared recently and wasn't in early scans
        if total_snapshots >= 3:
            first_snapshot_ids = set(timeline["snapshots"][0].get("device_ids", []))
            if device_id not in first_snapshot_ids and entry["seen_count"] > 1:
                reasons.append("Appeared after initial scan (new device)")

        # Night-only pattern: check window timestamps
        night_windows = 0
        day_windows = 0
        for w in entry["windows"]:
            try:
                start_hour = datetime.fromisoformat(
                    w["start"].replace("Z", "+00:00")
                ).hour
                if 22 <= start_hour or start_hour <= 6:
                    night_windows += 1
                else:
                    day_windows += 1
            except (ValueError, TypeError):
                pass
        if night_windows >= 2 and day_windows == 0:
            reasons.append(f"Night-only: seen only between 10 PM – 6 AM ({night_windows} windows)")

        if reasons:
            suspicious.append({
                "device_id": device_id,
                "name": entry["name"],
                "ip": entry["ip"],
                "risk": entry["risk"],
                "reasons": reasons,
                "seen_count": entry["seen_count"],
                "windows": len(entry["windows"]),
            })

    # Sort by number of reasons (most suspicious first)
    suspicious.sort(key=lambda x: len(x["reasons"]), reverse=True)
    return suspicious


def format_timeline() -> str:
    """Format the device timeline for display."""
    timeline = _load_timeline()
    if not timeline["devices"]:
        return "  No timeline data yet. Run --record to start tracking."

    lines = []
    total = len(timeline["snapshots"])
    lines.append(f"  {len(timeline['devices'])} devices across {total} snapshots\n")

    # Sort by risk level, then by last seen
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "LOW": 3, "INFO": 4}
    sorted_devices = sorted(
        timeline["devices"].items(),
        key=lambda x: (risk_order.get(x[1]["risk"], 5), x[1]["last_seen"]),
    )

    for device_id, entry in sorted_devices:
        risk = entry["risk"]
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MODERATE": "🟡", "LOW": "🟢"}.get(risk, "🔵")
        ratio = entry["seen_count"] / total if total else 0

        # Presence bar (20 chars wide)
        bar_len = 20
        filled = round(ratio * bar_len)
        bar = "█" * filled + "░" * (bar_len - filled)

        lines.append(f"  {icon} {entry['name'][:25]:<25} {entry['ip']:<16} [{bar}] {ratio:.0%}")
        lines.append(f"     {device_id}  seen {entry['seen_count']}x  {len(entry['windows'])} window(s)")

        # Show time range
        try:
            first = datetime.fromisoformat(entry["first_seen"].replace("Z", "+00:00"))
            last = datetime.fromisoformat(entry["last_seen"].replace("Z", "+00:00"))
            lines.append(f"     {first.strftime('%m/%d %H:%M')} → {last.strftime('%m/%d %H:%M')}")
        except (ValueError, TypeError):
            pass

        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Device timeline tracker")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--record", action="store_true", help="Record a snapshot now")
    group.add_argument("--show", action="store_true", help="Display timeline")
    group.add_argument("--watch", type=int, metavar="MINUTES", help="Auto-record every N minutes")
    group.add_argument("--suspicious", action="store_true", help="Show suspicious patterns")
    group.add_argument("--reset", action="store_true", help="Clear all timeline data")
    args = parser.parse_args()

    print(f"\n  Device Timeline")
    print(f"  {'=' * 40}")

    if args.record:
        print(f"  Running scan...")
        snap = record_snapshot()
        print(f"  ✓ Recorded {snap['device_count']} devices at {snap['timestamp'][:19]}")

    elif args.show:
        print(f"\n{format_timeline()}")

    elif args.watch:
        interval = args.watch
        print(f"  Auto-recording every {interval} minutes. Press Ctrl+C to stop.\n")
        try:
            while True:
                print(f"  [{datetime.now().strftime('%H:%M:%S')}] Scanning...", end=" ", flush=True)
                snap = record_snapshot()
                print(f"✓ {snap['device_count']} devices")
                time.sleep(interval * 60)
        except KeyboardInterrupt:
            print(f"\n\n  Stopped. Use --show to view the timeline.\n")

    elif args.suspicious:
        suspicious = analyze_suspicious()
        if suspicious:
            print(f"\n  ⚠️  {len(suspicious)} device(s) with unusual patterns:\n")
            for s in suspicious:
                risk = s["risk"]
                icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MODERATE": "🟡"}.get(risk, "🟡")
                print(f"  {icon} {s['name']} ({s['ip']})")
                for reason in s["reasons"]:
                    print(f"     → {reason}")
                print()
        else:
            print(f"\n  ✓ No suspicious activity patterns detected.")
            print(f"  Keep recording snapshots over time for better analysis.\n")

    elif args.reset:
        if TIMELINE_FILE.exists():
            TIMELINE_FILE.unlink()
            print(f"  ✓ Timeline data cleared.")
        else:
            print(f"  No timeline data to clear.")

    print()


if __name__ == "__main__":
    main()
