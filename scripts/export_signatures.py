#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Export detection signatures from scan.py / detectors.py to JSON for the
mobile app, so both tools share one source of truth.

    python3 scripts/export_signatures.py   # writes mobile/src/data/signatures.json
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import detectors  # noqa: E402
import scan  # noqa: E402
import spydevices  # noqa: E402

try:
    import sinkhole as sinkhole_mod  # noqa: E402
except ImportError:
    sinkhole_mod = None  # type: ignore[assignment]


def _js_pattern(compiled_re: "re.Pattern[str]") -> str:
    """Strip Python-only inline flags like (?i) so the pattern is valid JS."""
    import re as _re
    return _re.sub(r"^\(\?[aiLmsux]+\)", "", compiled_re.pattern)


def main() -> None:
    data = {
        "_generated_by": "scripts/export_signatures.py — do not edit by hand",
        "tier1Ouis": scan.TIER1_OUIS,
        "tier2Ouis": scan.TIER2_OUIS,
        "cameraPorts": [int(p) for p in scan.CAMERA_PORTS.split(",")],
        "rtspPorts": sorted(int(p) for p in scan.RTSP_PORTS),
        "httpPorts": sorted(int(p) for p in scan.HTTP_PORTS),
        "vendorPorts": sorted(int(p) for p in scan.VENDOR_PORTS),
        "weakVendorPorts": sorted(int(p) for p in scan.WEAK_VENDOR_PORTS),
        "rtspPaths": detectors.RTSP_PATHS,
        "cameraKeywordsHigh": scan.CAMERA_KEYWORDS_HIGH,
        "cameraHeaders": scan.CAMERA_HEADERS,
        "cameraTitle": _js_pattern(scan.CAMERA_TITLE_RE),
        "cameraMfrKeywords": _js_pattern(scan.CAMERA_MFR_KEYWORDS),
        "cameraHostname": _js_pattern(scan.CAMERA_HOSTNAME_RE),
        "cameraNameStrong": _js_pattern(detectors.CAMERA_NAME_STRONG),
        "cameraNameWeak": _js_pattern(detectors.CAMERA_NAME_WEAK),
        "physicalChecklist": scan.PHYSICAL_CHECKLIST,
        "spyOuis": spydevices.SPY_OUIS,
        "spyModelPattern": _js_pattern(spydevices.SPY_MODEL_PATTERNS),
        "spyHttpServers": _js_pattern(spydevices.SPY_HTTP_SERVERS),
        "p2pPorts": sorted(spydevices.P2P_PORTS),
        "spyPortCombos": [
            {"ports": sorted(combo), "desc": desc}
            for combo, desc in spydevices.SPY_PORT_COMBOS
        ],
        "p2pDomains": spydevices.P2P_DOMAINS,
        "sinkholeDomains": sinkhole_mod.SINKHOLE_DOMAINS if sinkhole_mod else spydevices.P2P_DOMAINS,
    }
    out = ROOT / "mobile" / "src" / "data" / "signatures.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
