#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Baseline and trust list for privacy-scanner.

- Known devices are remembered per network (keyed by the gateway's MAC), so
  devices that appear after the first scan stand out as NEW.
- Trusted devices (the user's own phone, laptop...) are global, so they stay
  trusted on every network.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path


def _norm(mac: str) -> str:
    return mac.upper().replace("-", ":")


def _load(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


class Baseline:
    def __init__(self, directory: Path):
        self.dir = directory
        self.trusted_path = directory / "trusted.json"
        self.trusted: dict[str, str] = _load(self.trusted_path)
        self.known_path: Path | None = None
        self.known: dict[str, dict] = {}

    def use_network(self, network_id: str) -> None:
        """Select the per-network known-device list (e.g. the gateway MAC)."""
        safe = re.sub(r"[^0-9A-Za-z]+", "-", network_id).strip("-") or "default"
        self.known_path = self.dir / f"baseline-{safe}.json"
        self.known = _load(self.known_path)

    def trust(self, mac: str, label: str = "") -> None:
        self.trusted[_norm(mac)] = label or "trusted"
        _save(self.trusted_path, self.trusted)

    def is_trusted(self, mac: str) -> bool:
        return _norm(mac) in self.trusted

    def label(self, mac: str) -> str:
        return self.trusted.get(_norm(mac), "")

    def is_new(self, mac: str) -> bool:
        """True only when this network has a baseline that never saw this MAC."""
        return bool(self.known) and bool(mac) and _norm(mac) not in self.known

    def record(self, devices: list[dict], room: str = "") -> None:
        if self.known_path is None:
            return
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        for d in devices:
            mac = _norm(d.get("mac", ""))
            if not mac:
                continue
            entry = self.known.setdefault(mac, {"first_seen": now})
            entry.update({"last_seen": now, "where": d.get("ip", ""),
                          "manufacturer": d.get("manufacturer", "")})
            if room:
                rooms = set(entry.get("rooms", []))
                rooms.add(room)
                entry["rooms"] = sorted(rooms)

    # ── Multi-room comparison ──

    def room_dir(self) -> Path:
        return self.dir / "rooms"

    def save_room_scan(self, room: str, devices: list[dict]) -> None:
        """Save a snapshot of devices found in a named room."""
        rdir = self.room_dir()
        rdir.mkdir(parents=True, exist_ok=True)
        safe = re.sub(r"[^0-9A-Za-z]+", "-", room.lower()).strip("-") or "room"
        data = {
            "room": room,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "devices": [
                {
                    "mac": _norm(d.get("mac", "")),
                    "ip": d.get("ip", ""),
                    "manufacturer": d.get("manufacturer", ""),
                    "risk": d.get("risk", "INFO"),
                    "device_type": d.get("device_type", ""),
                }
                for d in devices if d.get("mac")
            ],
        }
        _save(rdir / f"{safe}.json", data)

    def load_room_scans(self) -> dict[str, list[dict]]:
        """Load all saved room scans: room_name -> [device dicts]."""
        rdir = self.room_dir()
        rooms: dict[str, list[dict]] = {}
        if not rdir.is_dir():
            return rooms
        for p in sorted(rdir.glob("*.json")):
            data = _load(p)
            name = data.get("room", p.stem)
            rooms[name] = data.get("devices", [])
        return rooms

    def compare_rooms(self) -> list[dict]:
        """Find devices that appear in only one room — more suspicious than
        devices seen everywhere (which are likely a router, NAS, etc.)."""
        rooms = self.load_room_scans()
        if len(rooms) < 2:
            return []
        mac_rooms: dict[str, set[str]] = {}
        mac_info: dict[str, dict] = {}
        for room_name, devices in rooms.items():
            for d in devices:
                mac = d.get("mac", "")
                if not mac:
                    continue
                mac_rooms.setdefault(mac, set()).add(room_name)
                mac_info[mac] = d
        single_room: list[dict] = []
        for mac, seen_in in mac_rooms.items():
            if len(seen_in) == 1:
                info = mac_info[mac]
                info["only_in"] = list(seen_in)[0]
                info["room_count"] = 1
                info["total_rooms"] = len(rooms)
                single_room.append(info)
        return single_room
        _save(self.known_path, self.known)
