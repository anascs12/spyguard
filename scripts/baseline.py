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

    def record(self, devices: list[dict]) -> None:
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
        _save(self.known_path, self.known)
