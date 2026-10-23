#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Evidence pack for privacy-scanner.

Bundles the HTML/JSON reports and raw tool output into one zip with a
SHA-256 manifest, so a report to a platform or the police can show the
files were not altered after the scan.
"""

from __future__ import annotations

import hashlib
import json
import platform
import time
import zipfile
from pathlib import Path


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def build_pack(out_zip: Path, report_files: list[Path], raw_dir: Path, meta: dict) -> Path:
    files: list[tuple[Path, str]] = [(p, p.name) for p in report_files if p.exists()]
    if raw_dir.is_dir():
        files += [(p, f"raw/{p.relative_to(raw_dir)}") for p in sorted(raw_dir.rglob("*")) if p.is_file()]

    manifest = {
        "created": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "host": platform.node(),
        "platform": platform.platform(),
        "scan": meta,
        "files": {arc: _sha256(p) for p, arc in files},
    }
    manifest_text = json.dumps(manifest, indent=2)
    with zipfile.ZipFile(out_zip, "w", zipfile.ZIP_DEFLATED) as z:
        for p, arc in files:
            z.write(p, arc)
        z.writestr("MANIFEST.json", manifest_text)
        z.writestr("MANIFEST.sha256", hashlib.sha256(manifest_text.encode()).hexdigest() + "  MANIFEST.json\n")
    return out_zip
