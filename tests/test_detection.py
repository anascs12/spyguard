# SPDX-License-Identifier: Apache-2.0
"""Offline tests for detection and classification logic. Run: python3 -m unittest"""

import contextlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import detectors  # noqa: E402
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


if __name__ == "__main__":
    unittest.main()
