# SPDX-License-Identifier: Apache-2.0
"""Offline tests for detection and classification logic. Run: python3 -m unittest"""

import contextlib
import io
import json
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import detectors  # noqa: E402
import preview  # noqa: E402
import scan  # noqa: E402


def fake_server(reply_for):
    """Tiny TCP server; reply_for(request_text) -> response bytes."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            with conn:
                req = conn.recv(4096).decode()
                conn.sendall(reply_for(req))

    threading.Thread(target=loop, daemon=True).start()
    return srv, str(srv.getsockname()[1])


def no_lookup(mac):
    return "", 0


def rtp_test_video():
    """RTP/JPEG packets of ffmpeg's test pattern, as a real camera would send them."""
    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind(("127.0.0.1", 0))
    rx.settimeout(0.5)
    packets = []

    def collect():
        while True:
            try:
                packets.append(rx.recv(65536))
            except OSError:
                return

    t = threading.Thread(target=collect, daemon=True)
    t.start()
    subprocess.run(
        ["ffmpeg", "-nostdin", "-loglevel", "error", "-re", "-f", "lavfi", "-i", "testsrc=size=640x360:rate=10",
         "-t", "0.5", "-c:v", "mjpeg", "-huffman", "default", "-pix_fmt", "yuvj420p", "-q:v", "5",
         "-f", "rtp", f"rtp://127.0.0.1:{rx.getsockname()[1]}"], check=True, stdout=subprocess.DEVNULL)
    t.join()
    rx.close()
    return packets


def rtsp_camera(packets, protected):
    """Minimal RTSP camera on localhost. Returns (socket, port, requests seen)."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    seen = []

    def serve(conn):
        with conn, contextlib.suppress(OSError):  # the client hangs up once it has its frame
            handle(conn)

    def handle(conn):
        buf = b""
        while True:
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head, _, buf = buf.partition(b"\r\n\r\n")
            req = head.decode("latin-1")
            seen.append(req)
            method = req.split(" ", 1)[0]
            cseq = next((ln.split(":", 1)[1].strip() for ln in req.splitlines()
                         if ln.lower().startswith("cseq:")), "0")
            ok = f"RTSP/1.0 200 OK\r\nCSeq: {cseq}\r\nServer: TestCam\r\n"
            if method == "OPTIONS":
                conn.sendall((ok + "Public: OPTIONS, DESCRIBE, SETUP, PLAY, TEARDOWN\r\n\r\n").encode())
            elif protected:
                conn.sendall(f"RTSP/1.0 401 Unauthorized\r\nCSeq: {cseq}\r\n"
                             'WWW-Authenticate: Basic realm="cam"\r\n\r\n'.encode())
            elif method == "DESCRIBE":
                sdp = ("v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=cam\r\nt=0 0\r\n"
                       "m=video 0 RTP/AVP 26\r\na=control:track1\r\n")
                conn.sendall((ok + f"Content-Type: application/sdp\r\nContent-Length: {len(sdp)}"
                              f"\r\n\r\n{sdp}").encode())
            elif method == "SETUP":
                conn.sendall((ok + "Transport: RTP/AVP/TCP;unicast;interleaved=0-1\r\nSession: 1\r\n\r\n").encode())
            elif method == "PLAY":
                conn.sendall((ok + "Session: 1\r\n\r\n").encode())
                for pkt in packets * 20:
                    conn.sendall(b"$\x00" + struct.pack(">H", len(pkt)) + pkt)
            else:
                conn.sendall((ok + "\r\n").encode())

    def loop():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            threading.Thread(target=serve, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return srv, str(srv.getsockname()[1]), seen


class RtspProbeTest(unittest.TestCase):
    def test_password_protected_camera(self):
        def reply(req):
            if req.startswith("OPTIONS"):
                return b"RTSP/1.0 200 OK\r\nCSeq: 1\r\nServer: Hipcam RealServer\r\nPublic: OPTIONS, DESCRIBE\r\n\r\n"
            return b"RTSP/1.0 401 Unauthorized\r\nCSeq: 2\r\n\r\n"
        srv, port = fake_server(reply)
        res = detectors.probe_rtsp("127.0.0.1", port)
        srv.close()
        self.assertEqual(res["server"], "Hipcam RealServer")
        self.assertTrue(res["auth_required"])
        self.assertEqual(res["open_stream"], "")

    def test_open_stream(self):
        sdp = b"v=0\r\nm=video 0 RTP/AVP 96\r\n"
        def reply(req):
            if req.startswith("OPTIONS"):
                return b"RTSP/1.0 200 OK\r\nCSeq: 1\r\n\r\n"
            return b"RTSP/1.0 200 OK\r\nContent-Length: %d\r\n\r\n%s" % (len(sdp), sdp)
        srv, port = fake_server(reply)
        res = detectors.probe_rtsp("127.0.0.1", port)
        srv.close()
        self.assertEqual(res["open_stream"], "/")

    def test_http_server_is_not_rtsp(self):
        srv, port = fake_server(lambda req: b"HTTP/1.1 400 Bad Request\r\n\r\n")
        self.assertIsNone(detectors.probe_rtsp("127.0.0.1", port))
        srv.close()


class RadioClassifyTest(unittest.TestCase):
    def test_camera_hotspots(self):
        lookup = lambda mac: ("Hikvision", 1) if mac.startswith("C0:56:E3") else ("", 0)
        aps = [
            {"bssid": "AA:AA:AA:00:00:01", "ssid": "IPC-365821", "channel": "6", "signal_dbm": -48.0},
            {"bssid": "C0:56:E3:00:00:02", "ssid": "HAP-1234", "channel": "1", "signal_dbm": -60.0},
            {"bssid": "AA:AA:AA:00:00:03", "ssid": "Camila's WiFi", "channel": "11", "signal_dbm": -40.0},
            {"bssid": "AA:AA:AA:00:00:04", "ssid": "Living room cam", "channel": "11", "signal_dbm": -80.0},
        ]
        risks = {f["mac"]: f["risk"] for f in detectors.classify_aps(aps, lookup)}
        self.assertEqual(risks, {
            "AA:AA:AA:00:00:01": "HIGH",
            "C0:56:E3:00:00:02": "CRITICAL",
            "AA:AA:AA:00:00:04": "MODERATE",
        })

    def test_ble_trackers(self):
        base = {"name": "", "rssi": -50, "manufacturer_data": {}, "services": set(), "service_data": {}}
        devices = [
            dict(base, address="A1", manufacturer_data={0x004C: b"\x12\x19\x10" + bytes(25)}),  # AirTag, separated
            dict(base, address="A2", services={"feed"}),
            dict(base, address="A3", name="V380_CAM"),
            dict(base, address="A4", name="JBL Flip 5"),
            dict(base, address="A5", manufacturer_data={0x004C: b"\x12\x02\x00\x02"}),  # iPhone near owner
            dict(base, address="A6", manufacturer_data={0x004C: b"\x12\x19\x00" + bytes(25)}),  # offline iPhone
            dict(base, address="A7", rssi=-90, manufacturer_data={0x004C: b"\x12\x19\x10" + bytes(25)}),
        ]
        risks = {f["mac"]: f["risk"] for f in detectors.classify_ble(devices)}
        self.assertEqual(risks, {"A1": "HIGH", "A2": "MODERATE", "A3": "HIGH", "A7": "LOW"})

    def test_monitor_streaming_station(self):
        cap = detectors.MonitorCapture("wlan0")
        cap.dwell = {6: 10.0}
        cap.aps = {"BB:BB:BB:BB:BB:BB": {"ssid": "Neighbour", "rssi": -70, "channel": 6}}
        base = {"bssid": "BB:BB:BB:BB:BB:BB", "channel": 6, "up_frames": 2000, "down_frames": 300}
        cap.stations = {
            "02:00:00:00:00:01": dict(base, rssi=-50, up_bytes=2_000_000, down_bytes=40_000),
            "02:00:00:00:00:02": dict(base, rssi=-85, up_bytes=2_000_000, down_bytes=40_000),
            "02:00:00:00:00:03": dict(base, rssi=-50, up_bytes=20_000, down_bytes=900_000),
        }
        risks = {f["mac"]: f["risk"] for f in cap.findings(no_lookup, set())}
        self.assertEqual(risks, {"02:00:00:00:00:01": "HIGH", "02:00:00:00:00:02": "MODERATE"})

    def test_trilateration(self):
        # Device at (2, 1): distances from three corners
        pts = [(0, 0, 5 ** 0.5), (4, 0, 5 ** 0.5), (0, 3, 8 ** 0.5)]
        x, y = detectors._trilaterate(pts)
        self.assertAlmostEqual(x, 2, delta=0.15)
        self.assertAlmostEqual(y, 1, delta=0.15)


class ClassifyTest(unittest.TestCase):
    def make_ctx(self, tmp):
        sys.argv = ["scan.py", "--output-dir", tmp, "--lang", "en"]
        ctx = scan.ScanContext(scan.parse_args())
        ctx.baseline.use_network("test-net")
        return ctx

    def classify(self, ctx):
        with contextlib.redirect_stdout(io.StringIO()):
            scan.phase6_classify(ctx)
        return {c["ip"]: c for c in ctx.classifications}

    def test_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self.make_ctx(tmp)
            dev = lambda ip, mac, cls, host="": {"ip": ip, "mac": mac, "manufacturer": "",
                                                  "classification": cls, "oui": "", "hostname": host}
            ctx.oui_results = [
                dev("10.0.0.2", "11:22:33:00:00:02", "UNKNOWN"),          # port 8000 only
                dev("10.0.0.3", "11:22:33:00:00:03", "UNKNOWN"),          # real RTSP
                dev("10.0.0.4", "11:22:33:00:00:04", "KNOWN_SAFE"),       # ONVIF says camera
                dev("10.0.0.5", "11:22:33:00:00:05", "KNOWN_OTHER", "ipcam-garden"),
                dev("10.0.0.6", "11:22:33:00:00:06", "UNKNOWN"),          # trusted
            ]
            ctx.port_results = [{"ip": "10.0.0.2", "port": "8000"}, {"ip": "10.0.0.3", "port": "554"}]
            ctx.deep_results = [{"ip": "10.0.0.3", "port": "554", "type": "RTSP_CONFIRMED", "detail": "RTSP server"}]
            ctx.onvif = {"10.0.0.4": {"manufacturer": "Acme", "model": "C1", "name": "", "hardware": ""}}
            ctx.baseline.trust("11:22:33:00:00:06", "my laptop")
            ctx.radio_results = [detectors.finding("HIGH", "ble", "A1", "", "Tile", "x", "y")]
            r = self.classify(ctx)
            self.assertEqual(r["10.0.0.2"]["risk"], "MODERATE")
            self.assertEqual(r["10.0.0.3"]["risk"], "CRITICAL")
            self.assertEqual(r["10.0.0.4"]["risk"], "CRITICAL")
            self.assertEqual(r["10.0.0.5"]["risk"], "HIGH")
            self.assertEqual(r["10.0.0.6"]["risk"], "INFO")
            self.assertIn("my laptop", r["10.0.0.6"]["device_type"])
            self.assertEqual(r["ble"]["risk"], "HIGH")
            self.assertEqual(sum(ctx.counts.values()), 6)

            # Second scan on the same network: a new device is flagged NEW
            ctx.baseline.record(ctx.classifications)
            ctx.classifications, ctx.radio_results = [], []
            ctx.counts = dict.fromkeys(ctx.counts, 0)
            ctx.oui_results.append(dev("10.0.0.9", "11:22:33:00:00:09", "UNKNOWN"))
            r = self.classify(ctx)
            self.assertTrue(r["10.0.0.9"]["new"])
            self.assertFalse(r["10.0.0.2"]["new"])

            # HTML report renders from results.json
            out = os.path.join(tmp, "r.html")
            subprocess.run([sys.executable, str(SCRIPTS / "report_html.py"), "--classifications",
                            os.path.join(ctx.scan_dir, "results.json"), "--output", out, "--lang", "en"],
                           check=True)
            page = Path(out).read_text(encoding="utf-8")
            self.assertIn("ipcam-garden", page)
            self.assertIn("Physical Check", page)
            data = json.loads(Path(ctx.scan_dir, "results.json").read_text(encoding="utf-8"))
            self.assertEqual(data["counts"]["CRITICAL"], 2)


class CredentialAuditTest(unittest.TestCase):
    """A default-password camera is surfaced loudly; the audit only tests, never streams."""

    def ctx_with_camera(self, tmp, extra_args=()):
        sys.argv = ["scan.py", "--output-dir", tmp, "--lang", "en", *extra_args]
        ctx = scan.ScanContext(scan.parse_args())
        ctx.baseline.use_network("test-net")
        ctx.has_nmap = True
        ctx.oui_results = [
            {"ip": "10.0.0.3", "mac": "11:22:33:00:00:03", "manufacturer": "",
             "classification": "UNKNOWN", "oui": "", "hostname": ""},
            {"ip": "10.0.0.8", "mac": "11:22:33:00:00:08", "manufacturer": "",
             "classification": "KNOWN_SAFE", "oui": "", "hostname": ""},  # laptop, no camera ports
        ]
        ctx.port_results = [{"ip": "10.0.0.3", "port": "554"}, {"ip": "10.0.0.8", "port": "445"}]
        ctx.deep_results = [{"ip": "10.0.0.3", "port": "554", "type": "RTSP_CONFIRMED", "detail": "RTSP server"}]
        return ctx

    def run_scan(self, ctx):
        with contextlib.redirect_stdout(io.StringIO()):
            scan.phase5d_credentials(ctx)
            scan.phase6_classify(ctx)
        return {c["ip"]: c for c in ctx.classifications}

    def test_default_password_surfaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self.ctx_with_camera(tmp, ["--credential-audit"])
            audited = []
            hit = scan.onvif_mod.AuditResult(
                ip="10.0.0.3", port=554, protocol="RTSP", username="admin",
                password="(empty)", brand_hint="XMEye IPC", accessible=True, device_info="RTSP stream at /")

            def fake_audit(ip, ports=None):
                audited.append(ip)
                return [hit] if ip == "10.0.0.3" else []

            with mock.patch.object(scan.onvif_mod, "audit_target", side_effect=fake_audit):
                r = self.run_scan(ctx)
            # Only the camera-like host was tested, never the laptop
            self.assertEqual(audited, ["10.0.0.3"])
            cam = r["10.0.0.3"]
            self.assertEqual(cam["risk"], "CRITICAL")
            self.assertEqual(cam["device_type"], "Unsecured camera (default password)")
            self.assertTrue(cam["cred_default"])
            self.assertIn("default login", cam["evidence"])
            self.assertIn("report it", cam["recommendation"].lower())

            out = os.path.join(tmp, "r.html")
            subprocess.run([sys.executable, str(SCRIPTS / "report_html.py"), "--classifications",
                            os.path.join(ctx.scan_dir, "results.json"), "--output", out, "--lang", "en"],
                           check=True)
            page = Path(out).read_text(encoding="utf-8")
            self.assertIn("Factory-default password", page)
            self.assertIn("never views the video", page)

    def test_off_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            ctx = self.ctx_with_camera(tmp)  # no --credential-audit
            with mock.patch.object(scan.onvif_mod, "audit_target",
                                   side_effect=AssertionError("must not audit without the flag")):
                r = self.run_scan(ctx)
            self.assertEqual(ctx.credentials, {})
            self.assertNotIn("cred_default", r["10.0.0.3"])


@unittest.skipUnless(shutil.which("ffmpeg"), "needs ffmpeg")
class CameraViewTest(unittest.TestCase):
    """A still is saved from streams with no password, and nothing is ever sent to a locked one."""

    @classmethod
    def setUpClass(cls):
        cls.packets = rtp_test_video()

    def scan_camera(self, tmp, port):
        sys.argv = ["scan.py", "--output-dir", tmp, "--lang", "en"]
        ctx = scan.ScanContext(scan.parse_args())
        ctx.baseline.use_network("test-net")
        ctx.oui_results = [{"ip": "127.0.0.1", "mac": "11:22:33:00:00:07", "manufacturer": "",
                            "classification": "UNKNOWN", "oui": "", "hostname": ""}]
        ctx.port_results = [{"ip": "127.0.0.1", "port": port}]
        with contextlib.redirect_stdout(io.StringIO()), mock.patch.object(scan, "RTSP_PORTS", {port}):
            scan.phase5_deep_inspection(ctx)
            scan.phase6_classify(ctx)
        return ctx, ctx.classifications[0]

    def test_open_stream_is_shown(self):
        srv, port, seen = rtsp_camera(self.packets, protected=False)
        with tempfile.TemporaryDirectory() as tmp:
            ctx, device = self.scan_camera(tmp, port)
            srv.close()
            self.assertEqual(device["risk"], "CRITICAL")
            self.assertTrue(preview.is_preview_uri(device["preview"]))
            self.assertIn("what this camera sees", device["recommendation"])
            still = Path(ctx.scan_dir, device["preview_file"]).read_bytes()
            self.assertTrue(still.startswith(b"\xff\xd8"))
            self.assertEqual(preview.hashlib.sha256(still).hexdigest(), device["preview_sha256"])
            self.assertFalse(any("authorization:" in r.lower() for r in seen))

            # The raw folder goes into the evidence pack, so the still is hashed with it
            pack = scan.evidence.build_pack(Path(tmp, "e.zip"), [], Path(ctx.scan_dir), {})
            with scan.evidence.zipfile.ZipFile(pack) as z:
                manifest = json.loads(z.read("MANIFEST.json"))
            self.assertEqual(manifest["files"][f"raw/{device['preview_file']}"], device["preview_sha256"])

            out = os.path.join(tmp, "r.html")
            subprocess.run([sys.executable, str(SCRIPTS / "report_html.py"), "--classifications",
                            os.path.join(ctx.scan_dir, "results.json"), "--output", out, "--lang", "en"],
                           check=True)
            self.assertIn('<img class="camera-view" src="data:image/jpeg;base64,',
                          Path(out).read_text(encoding="utf-8"))

    def test_locked_stream_is_left_alone(self):
        srv, port, seen = rtsp_camera(self.packets, protected=True)
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(preview, "grab_frame", side_effect=AssertionError("must not be called")):
            ctx, device = self.scan_camera(tmp, port)
            srv.close()
            self.assertEqual(device["risk"], "CRITICAL")
            self.assertNotIn("preview", device)
            self.assertEqual(ctx.previews, {})
            self.assertIn("never tries to log in", device["recommendation"])
            # Only the unauthenticated probe: no credentials, no attempt to start the stream
            self.assertEqual({r.split(" ", 1)[0] for r in seen}, {"OPTIONS", "DESCRIBE"})
            self.assertFalse(any("authorization:" in r.lower() for r in seen))

    def test_preview_can_be_switched_off(self):
        srv, port, seen = rtsp_camera(self.packets, protected=False)
        with tempfile.TemporaryDirectory() as tmp:
            sys.argv = ["scan.py", "--output-dir", tmp, "--no-preview"]
            ctx = scan.ScanContext(scan.parse_args())
            with contextlib.redirect_stdout(io.StringIO()):
                scan._capture_preview(ctx, "127.0.0.1", port, "/")
            srv.close()
            self.assertEqual(ctx.previews, {})
            self.assertEqual(seen, [])

    def test_stream_url_never_has_credentials(self):
        self.assertEqual(preview.stream_url("10.0.0.3", "554", "/live"), "rtsp://10.0.0.3:554/live")

    def test_only_our_own_data_uri_is_embedded(self):
        self.assertTrue(preview.is_preview_uri("data:image/jpeg;base64,/9j/4AAQ"))
        for bad in ("", None, "javascript:alert(1)", "data:image/svg+xml;base64,PHN2Zz4=",
                    'data:image/jpeg;base64,AA"><script>', "https://example.com/a.jpg"):
            self.assertFalse(preview.is_preview_uri(bad))


if __name__ == "__main__":
    unittest.main()
