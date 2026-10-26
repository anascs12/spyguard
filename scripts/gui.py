#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
SpyGuard desktop app: a local web UI for the laptop scanner.

Started by the ./spyguard launcher (which asks for the password via the
system dialog). Serves a single page on 127.0.0.1, runs scan.py in the
background, turns its output into plain-language progress, streams live
signal strength for "Find it", and shares results with the phone app.

Everything stays on this computer: the UI listens on localhost only and
every request needs the random token the launcher put in the URL. The
phone link listens on the LAN, guarded by its own token.
"""

from __future__ import annotations

import argparse
import asyncio
import glob
import http.server
import json
import os
import queue
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import baseline as baseline_mod  # noqa: E402
import detectors  # noqa: E402
import scan  # noqa: E402

try:
    import timeline as timeline_mod  # noqa: E402
except ImportError:
    timeline_mod = None  # type: ignore[assignment]

try:
    import sinkhole as sinkhole_mod  # noqa: E402
except ImportError:
    sinkhole_mod = None  # type: ignore[assignment]

try:
    import onvif_audit as onvif_mod  # noqa: E402
except ImportError:
    onvif_mod = None  # type: ignore[assignment]

PAGE = HERE / "gui" / "index.html"
ANSI = re.compile(r"\x1b\[[0-9;]*m")

# scan.py phase number -> friendly step shown in the window
STEPS = [
    ("prep", "Getting ready", {"0", "0.5"}),
    ("lan", "Finding devices on this WiFi", {"1", "2", "3"}),
    ("services", "Asking devices what they are", {"4"}),
    ("nearby", "Checking nearby WiFi and Bluetooth", {"4b"}),
    ("verify", "Testing suspicious devices", {"5"}),
    ("air", "Listening for cameras on other networks", {"5b"}),
    ("traffic", "Watching for suspicious uploads", {"5c"}),
    ("results", "Preparing your results", {"6", "7"}),
]


class ScanJob:
    """One scan.py run, parsed into steps and messages."""

    def __init__(self, out_dir: Path, quick: bool, owner: int | None, deep: bool = False, room: str = ""):
        self.out_dir = out_dir
        self.quick = quick
        self.deep = deep
        self.room = room
        self.owner = owner
        self.state = "running"          # running | done | error
        self.step = 0
        self.message = "Starting…"
        self.alerts: list[str] = []
        self.started = time.time()
        self.results: dict | None = None
        self.report = ""
        self.error = ""
        self.proc: subprocess.Popen | None = None
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self) -> None:
        cmd = [sys.executable, "-u", str(HERE / "scan.py"), "--lang", "en", "--output-dir", str(self.out_dir)]
        if self.quick:
            cmd.append("--quick")
        if self.room:
            cmd.extend(["--room", self.room])
        if self.deep and os.geteuid() != 0:
            cmd = ["pkexec", *cmd]  # deep scan only: system password dialog
        elif not self.deep:
            cmd.append("--no-monitor")
        json_path = ""
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1)
            for raw in self.proc.stdout:  # type: ignore[union-attr]
                line = ANSI.sub("", raw).strip()
                m = re.match(r"Phase ([\d.]+[a-z]?):", line)
                if m:
                    for i, (_, _, phases) in enumerate(STEPS):
                        if m.group(1) in phases:
                            self.step = max(self.step, i)
                    continue
                m = re.match(r"\[(\+|\*|!|!!!)\]\s+(.*)", line)
                if m:
                    self.message = m.group(2)
                    if m.group(1) == "!!!" and len(self.alerts) < 50:
                        self.alerts.append(m.group(2))
                m = re.match(r"Results saved to:\s+(\S+\.json)", line)
                if m:
                    json_path = m.group(1)
            code = self.proc.wait()
            if self.deep and code in (126, 127) and not json_path:
                raise RuntimeError("The password was cancelled, so the deep scan didn’t run.")
            if code != 0 or not json_path:
                raise RuntimeError(self.message or f"scanner exited with code {code}")
            self.results = json.loads(Path(json_path).read_text(encoding="utf-8"))
            html_path = json_path[:-5] + ".html"
            self.report = html_path if os.path.exists(html_path) else ""
            self.state = "done"
            self.step = len(STEPS)
        except Exception as exc:  # surfaced in the window as a friendly error
            self.error = str(exc)
            self.state = "error"
        finally:
            if self.owner is not None:
                chown_tree(self.out_dir, self.owner)

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()

    def status(self) -> dict:
        return {
            "state": self.state,
            "step": self.step,
            "steps": [label for _, label, _ in STEPS],
            "message": self.message,
            "alerts": self.alerts[-5:],
            "elapsed": int(time.time() - self.started),
            "results": self.results,
            "hasReport": bool(self.report),
            "error": self.error,
        }


def chown_tree(path: Path, uid: int) -> None:
    """Files written as root under the user's home should belong to the user."""
    try:
        import pwd

        gid = pwd.getpwuid(uid).pw_gid
        for p in [path, *path.rglob("*")]:
            os.chown(p, uid, gid)
    except OSError:
        pass


class Locator:
    """Background RSSI reader for one target, feeding a queue."""

    def __init__(self, target: str, iface: str):
        self.q: queue.Queue = queue.Queue(maxsize=100)
        self.stop_event = threading.Event()
        self.cap: detectors.MonitorCapture | None = None
        kind, _, value = target.partition(":")
        threading.Thread(target=self._run, args=(kind, value, iface), daemon=True).start()

    def _put(self, item: dict) -> None:
        try:
            self.q.put_nowait(item)
        except queue.Full:
            pass

    def _run(self, kind: str, value: str, iface: str) -> None:
        try:
            if kind == "wifi":
                while not self.stop_event.is_set():
                    hit = [a for a in detectors.scan_wifi_aps(iface) if a["bssid"] == value.upper()]
                    self._put({"rssi": hit[0]["signal_dbm"] if hit else None})
                    self.stop_event.wait(2)
            elif kind == "ble":
                from bleak import BleakScanner

                def cb(dev, adv):
                    if dev.address.upper() == value.upper():
                        self._put({"rssi": adv.rssi})

                async def watch():
                    async with BleakScanner(detection_callback=cb):
                        while not self.stop_event.is_set():
                            await asyncio.sleep(0.5)

                asyncio.run(watch())
            elif kind == "mon":
                cap = detectors.MonitorCapture(iface, log=lambda m: self._put({"error": m}))
                if not detectors.monitor_supported(iface) or not cap.setup():
                    self._put({"error": "This laptop's WiFi card can't track devices by signal. "
                                        "A USB WiFi adapter with monitor mode makes this work."})
                    return
                self.cap = cap
                cap.target = value.upper()
                last = [0.0]

                def on_target(rssi, ch):
                    if time.time() - last[0] >= 0.5:
                        last[0] = time.time()
                        self._put({"rssi": rssi})

                cap.on_target = on_target
                try:
                    cap.run(duration=24 * 3600)
                finally:
                    cap.teardown()
            else:
                self._put({"error": "This device can't be tracked by signal."})
        except Exception as exc:
            self._put({"error": str(exc)})

    def stop(self) -> None:
        self.stop_event.set()
        if self.cap:
            self.cap.stop()


class DemoJob:
    """Finished job with sample results, for screenshots (--demo). Always labelled in the UI."""

    def __init__(self):
        sample = [
            ("CRITICAL", "192.168.1.37", "4C:BD:8F:21:9A:07", "Hikvision", "Surveillance Camera (confirmed)", "554,8000", "lan",
             "Surveillance manufacturer (Hikvision) + streaming/control ports open (554,8000)",
             "LIKELY ACTIVE CAMERA. Photograph device location. Contact the host or platform."),
            ("CRITICAL", "nearby-wifi", "C0:56:E3:4A:19:B2", "Hikvision", "Camera hotspot (brand + camera SSID)", "", "nearby-wifi",
             "SSID 'HAP-4A19B2', channel 6, -49 dBm — very close (likely same room/unit). Cameras broadcast their own network in setup mode.",
             "Not on your network: use '--locate wifi:C0:56:E3:4A:19:B2' and walk around to find it."),
            ("HIGH", "ble", "F2:31:8C:07:5D:AA", "Unknown", "Apple AirTag away from its owner", "", "ble",
             "Broadcasting the 'separated from owner' Find My beacon; -58 dBm — nearby (same or adjacent unit)",
             "Use '--locate ble:F2:31:8C:07:5D:AA' and walk around to find it."),
            ("MODERATE", "192.168.1.52", "E8:48:B8:10:22:3C", "Unknown", "Device with Possible Camera Port", "8000", "lan",
             "Port used by Hikvision/Reolink cameras open (8000), but also common on other devices",
             "Check what this device is; port alone is not proof of a camera."),
            ("INFO", "192.168.1.20", "F0:18:98:44:10:AB", "Apple", "Known Device", "", "lan",
             "Identified manufacturer: Apple", "Known device type, no camera indicators"),
            ("INFO", "192.168.1.1", "98:DA:C4:00:11:22", "TP-Link", "Known Device", "80", "lan",
             "Identified manufacturer: TP-Link", "Known device type, no camera indicators"),
        ]
        keys = ["risk", "ip", "mac", "manufacturer", "device_type", "open_ports", "source", "evidence", "recommendation"]
        self.results = {"devices": [dict(zip(keys, row)) for row in sample], "demo": True}
        self.report = ""
        self.state = "done"

    def stop(self) -> None:
        pass

    def status(self) -> dict:
        return {"state": "done", "step": len(STEPS), "steps": [s[1] for s in STEPS], "message": "",
                "alerts": [], "elapsed": 0, "results": self.results, "hasReport": False, "error": "", "demo": True}


class App:
    def __init__(self, token: str, out_dir: Path, owner: int | None):
        self.token = token
        self.out_dir = out_dir
        self.owner = owner
        self.job: ScanJob | None = None
        self.last_ping = time.time()
        self.iface = scan.detect_network().get("interface", "")
        self.phone_token = secrets.token_urlsafe(12)
        self.phone_port = 8765
        self.phone_server: http.server.ThreadingHTTPServer | None = None
        self.baseline = baseline_mod.Baseline(out_dir)

    def latest_results_file(self) -> str:
        files = sorted(glob.glob(str(self.out_dir / "privacy-scan-*.json")))
        return files[-1] if files else ""

    def start_phone_link(self) -> dict:
        """Serve the latest results to the phone app on the LAN."""
        if self.phone_server is None:
            app = self

            class PhoneHandler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    url = urllib.parse.urlparse(self.path)
                    given = urllib.parse.parse_qs(url.query).get("token", [""])[0]
                    path = app.latest_results_file()
                    if url.path != "/results.json":
                        self.send_error(404)
                    elif not secrets.compare_digest(given, app.phone_token):
                        self.send_error(403)
                    elif not path:
                        self.send_error(503, "No scan yet")
                    else:
                        body = Path(path).read_bytes()
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json; charset=utf-8")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)

                def log_message(self, *_args):
                    pass

            self.phone_server = http.server.ThreadingHTTPServer(("0.0.0.0", self.phone_port), PhoneHandler)
            threading.Thread(target=self.phone_server.serve_forever, daemon=True).start()
        ip = scan.detect_network().get("local_ip", "")
        link = f"privacyscanner://link?host={ip}&port={self.phone_port}&token={self.phone_token}"
        svg = ""
        try:
            import io

            import qrcode
            import qrcode.image.svg

            buf = io.BytesIO()
            qrcode.make(link, image_factory=qrcode.image.svg.SvgPathImage, border=2).save(buf)
            svg = buf.getvalue().decode()
        except ImportError:
            pass
        return {"link": link, "qr": svg, "ready": bool(self.latest_results_file())}


def make_handler(app: App):
    class Handler(http.server.BaseHTTPRequestHandler):
        def _authorized(self, query: dict) -> bool:
            return secrets.compare_digest(query.get("t", [""])[0], app.token)

        def _json(self, data, code: int = 200) -> None:
            body = json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(url.query)
            if not self._authorized(q):
                self.send_error(403, "Open SpyGuard from its launcher")
                return
            app.last_ping = time.time()
            if url.path == "/":
                body = PAGE.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
            elif url.path == "/api/ping":
                self._json({"ok": True})
            elif url.path == "/api/status":
                self._json({
                    "job": app.job.status() if app.job else None,
                    "monitor": detectors.monitor_supported(app.iface),
                    "nmap": bool(scan.shutil.which("nmap")),
                    "netReady": os.geteuid() == 0 or scan.has_net_caps("nmap"),
                    "trusted": app.baseline.trusted,
                })
            elif url.path == "/api/report":
                path = app.job.report if app.job else ""
                if not path:
                    self.send_error(404)
                    return
                body = Path(path).read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif url.path == "/api/phone":
                self._json(app.start_phone_link())
            elif url.path == "/api/locate":
                self._stream_locate(q.get("target", [""])[0])
            elif url.path == "/api/rooms":
                rooms = app.baseline.load_room_scans()
                singles = app.baseline.compare_rooms()
                self._json({"rooms": {name: len(devs) for name, devs in rooms.items()},
                            "singleRoom": singles})
            elif url.path == "/api/timeline":
                if timeline_mod:
                    self._json({"data": timeline_mod._load_timeline(),
                                "suspicious": timeline_mod.analyze_suspicious()})
                else:
                    self._json({"data": {"devices": {}, "snapshots": []}, "suspicious": []})
            elif url.path == "/api/sinkhole":
                if sinkhole_mod:
                    self._json({"enabled": sinkhole_mod.is_enabled(),
                                "domains": sinkhole_mod.get_blocked_domains()})
                else:
                    self._json({"enabled": False, "domains": [], "unavailable": True})
            else:
                self.send_error(404)

        def do_POST(self):
            url = urllib.parse.urlparse(self.path)
            q = urllib.parse.parse_qs(url.query)
            if not self._authorized(q):
                self.send_error(403)
                return
            length = int(self.headers.get("Content-Length") or 0)
            data = json.loads(self.rfile.read(length) or b"{}") if length else {}
            if url.path == "/api/scan":
                if app.job and app.job.state == "running":
                    self._json({"error": "A scan is already running"}, 409)
                    return
                app.job = ScanJob(app.out_dir, bool(data.get("quick")), app.owner, bool(data.get("deep")), str(data.get("room", "")))
                self._json({"ok": True})
            elif url.path == "/api/setup":
                # One-time: give only nmap/arp-scan raw-network capabilities (system password dialog)
                tools = [os.path.realpath(p) for p in map(scan.shutil.which, ("nmap", "arp-scan")) if p]
                ok = bool(tools)
                for tool in tools:
                    r = subprocess.run(["pkexec", "setcap", "cap_net_raw,cap_net_admin+eip", tool],
                                       capture_output=True, text=True)
                    ok = ok and r.returncode == 0
                self._json({"ok": ok and scan.has_net_caps("nmap")})
            elif url.path == "/api/stop":
                if app.job:
                    app.job.stop()
                self._json({"ok": True})
            elif url.path == "/api/sinkhole":
                action = str(data.get("action", ""))
                if not sinkhole_mod:
                    self._json({"error": "Sinkhole module not available"}, 500)
                elif action in ("enable", "disable"):
                    # Editing /etc/hosts needs root: run the CLI via the system
                    # password dialog (same as deep scans), unless already root.
                    cmd = [sys.executable, str(HERE / "sinkhole.py"), f"--{action}"]
                    if os.geteuid() != 0:
                        cmd = ["pkexec", *cmd]
                    r = subprocess.run(cmd, capture_output=True, text=True)
                    if r.returncode == 0:
                        if action == "enable":
                            self._json({"ok": True, "count": len(sinkhole_mod.get_blocked_domains())})
                        else:
                            self._json({"ok": True, "wasActive": True})
                    elif r.returncode in (126, 127):
                        self._json({"error": "Password cancelled"})
                    else:
                        self._json({"error": (r.stderr or r.stdout or "Failed").strip()[:200]})
                else:
                    self._json({"error": "action must be enable or disable"}, 400)
            elif url.path == "/api/timeline-record":
                if timeline_mod:
                    snap = timeline_mod.record_snapshot()
                    self._json({"ok": True, "snapshot": snap})
                else:
                    self._json({"error": "Timeline module not available"}, 500)
            elif url.path == "/api/onvif-audit":
                targets = data.get("targets", [])
                if not onvif_mod:
                    self._json({"error": "ONVIF audit module not available"}, 500)
                elif not targets:
                    self._json({"error": "No targets specified"}, 400)
                else:
                    results = []
                    for ip in targets[:10]:
                        results.extend(onvif_mod.audit_target(ip))
                    self._json({"results": [{"ip": r.ip, "port": r.port, "protocol": r.protocol,
                                             "username": r.username, "password": r.password, "brand": r.brand_hint,
                                             "device": r.device_info} for r in results]})
            elif url.path == "/api/trust":
                mac = str(data.get("mac", ""))
                if data.get("trusted", True):
                    app.baseline.trust(mac, str(data.get("label", "")) or "My device")
                else:
                    app.baseline.trusted.pop(mac.upper().replace("-", ":"), None)
                    baseline_mod._save(app.baseline.trusted_path, app.baseline.trusted)
                if app.owner is not None:
                    chown_tree(app.out_dir, app.owner)
                self._json({"ok": True, "trusted": app.baseline.trusted})
            else:
                self.send_error(404)

        def _stream_locate(self, target: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            loc = Locator(target, app.iface)
            try:
                while True:
                    try:
                        item = loc.q.get(timeout=5)
                    except queue.Empty:
                        item = {"keepalive": True}
                    app.last_ping = time.time()
                    self.wfile.write(f"data: {json.dumps(item)}\n\n".encode())
                    self.wfile.flush()
                    if "error" in item and target.startswith(("mon:", "ip:")):
                        break
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                loc.stop()

        def log_message(self, *_args):
            pass

    return Handler


def main() -> None:
    p = argparse.ArgumentParser(description="SpyGuard desktop app (started by ./spyguard)")
    p.add_argument("--port", type=int, default=8770)
    p.add_argument("--token", required=True)
    p.add_argument("--owner", type=int, default=None, help="uid that should own saved results")
    p.add_argument("--out-dir", default="")
    p.add_argument("--demo", action="store_true", help="Start with labelled sample results (screenshots)")
    args = p.parse_args()

    owner = args.owner if args.owner is not None else (int(os.environ["PKEXEC_UID"]) if "PKEXEC_UID" in os.environ else None)
    if args.out_dir:
        out_dir = Path(args.out_dir)
    elif owner is not None:
        import pwd

        out_dir = Path(pwd.getpwuid(owner).pw_dir) / "SpyGuard"
    else:
        out_dir = Path.home() / "SpyGuard"
    out_dir.mkdir(parents=True, exist_ok=True)
    if owner is not None:
        chown_tree(out_dir, owner)

    app = App(args.token, out_dir, owner)
    if args.demo:
        app.job = DemoJob()  # type: ignore[assignment]
    server = http.server.ThreadingHTTPServer(("127.0.0.1", args.port), make_handler(app))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f"SpyGuard running on http://127.0.0.1:{args.port}/?t=…", flush=True)

    # Quit when the window has been closed for a minute (no pings), unless scanning
    while True:
        time.sleep(5)
        busy = app.job and app.job.state == "running"
        if not busy and time.time() - app.last_ping > 60:
            break
    server.shutdown()
    if app.phone_server:
        app.phone_server.shutdown()


if __name__ == "__main__":
    main()
