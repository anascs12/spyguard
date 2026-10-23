#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Zigbee / Z-Wave sniffer — detect smart-home spy devices on 802.15.4 and Z-Wave.

Requires a CC2531 USB dongle (Zigbee) or a Sigma Designs / Silicon Labs Z-Wave
USB stick. Uses whsniff/zbdump for packet capture and parses frames for device
profiles that indicate cameras, microphones, or motion sensors.

Usage:
    sudo python3 zigbee.py                    # auto-detect dongle
    sudo python3 zigbee.py --channel 15       # specific Zigbee channel
    sudo python3 zigbee.py --zwave            # Z-Wave mode (if supported)
    sudo python3 zigbee.py --duration 120     # listen for 2 minutes
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import struct
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Zigbee device profiles (cluster IDs) that indicate surveillance hardware
# ---------------------------------------------------------------------------
ZIGBEE_CAMERA_CLUSTERS: dict[int, str] = {
    0x0501: "IAS ACE (security panel)",
    0x0502: "IAS WD (warning device)",
    0x0400: "Illuminance sensor",
    0x0406: "Occupancy sensor",
    0x0500: "IAS Zone (motion/contact sensor)",
}

ZIGBEE_SUSPICIOUS_PROFILES: dict[int, str] = {
    0x0104: "Home Automation",
    0x0109: "Smart Energy",
    0xC05E: "ZigBee Light Link",
}

# Known Zigbee camera manufacturer IDs
ZIGBEE_SPY_MANUFACTURERS: dict[str, str] = {
    "LUMI": "Aqara/Xiaomi (smart home camera ecosystem)",
    "IKEA": "IKEA DIRIGERA (can pair with cameras)",
    "eWeLink": "Sonoff (cheap IoT, camera-adjacent)",
    "Tuya": "Tuya (smart camera ecosystem)",
    "_TZ3000": "Tuya Zigbee generic (often cameras)",
    "Samsung": "SmartThings (camera integration)",
}

# Z-Wave command classes for surveillance devices
ZWAVE_CAMERA_CLASSES: dict[int, str] = {
    0x20: "Basic",
    0x30: "Sensor Binary (motion)",
    0x31: "Sensor Multilevel",
    0x71: "Notification (alarm/sensor)",
    0x80: "Battery (wireless device)",
    0x84: "Wake Up (sleepy node = sensor/camera)",
    0x98: "Security (encrypted traffic)",
    0x9F: "Security 2",
}


@dataclass
class ZigbeeDevice:
    short_addr: str = ""
    ieee_addr: str = ""
    manufacturer: str = ""
    profile: str = ""
    clusters: list[str] = field(default_factory=list)
    channel: int = 0
    rssi: int = 0
    suspicious: bool = False
    reason: str = ""
    frame_count: int = 0


@dataclass
class ZwaveDevice:
    node_id: int = 0
    home_id: str = ""
    command_classes: list[str] = field(default_factory=list)
    suspicious: bool = False
    reason: str = ""
    frame_count: int = 0


def _run(cmd: list[str], timeout: int = 10) -> tuple[str, str, int]:
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except FileNotFoundError:
        return "", "not found", -1


def find_cc2531() -> str | None:
    """Find a CC2531 USB dongle device path."""
    for dev in Path("/dev").glob("ttyACM*"):
        return str(dev)
    out, _, _ = _run(["lsusb"], timeout=5)
    if "0451:16a8" in out.lower() or "cc2531" in out.lower():
        for dev in Path("/dev/serial/by-id").glob("*cc2531*"):
            return str(dev)
    return None


def find_zwave_stick() -> str | None:
    """Find a Z-Wave USB stick device path."""
    for pattern in ["ttyUSB*", "ttyACM*"]:
        for dev in Path("/dev").glob(pattern):
            out, _, _ = _run(["udevadm", "info", str(dev)], timeout=5)
            if "sigma" in out.lower() or "z-wave" in out.lower() or "0658:0200" in out.lower():
                return str(dev)
    return None


# ---------------------------------------------------------------------------
# Zigbee capture via whsniff or TI sniffer tools
# ---------------------------------------------------------------------------

def capture_zigbee(channel: int = 15, duration: int = 60, device: str = "") -> list[ZigbeeDevice]:
    """Capture Zigbee traffic and identify devices."""
    devices: dict[str, ZigbeeDevice] = {}

    if not device:
        device = find_cc2531() or ""

    if shutil.which("whsniff") and device:
        return _capture_whsniff(channel, duration, device, devices)

    if shutil.which("zbdump"):
        return _capture_zbdump(channel, duration, devices)

    # Fallback: use TI packet sniffer output if available
    if shutil.which("python3"):
        return _capture_ti_sniffer(channel, duration, device, devices)

    return list(devices.values())


def _capture_whsniff(channel: int, duration: int, device: str,
                     devices: dict[str, ZigbeeDevice]) -> list[ZigbeeDevice]:
    """Capture using whsniff (outputs PCAP to stdout)."""
    import tempfile
    pcap_path = tempfile.mktemp(suffix=".pcap")

    try:
        with open(pcap_path, "wb") as f:
            proc = subprocess.Popen(
                ["whsniff", "-c", str(channel)],
                stdout=f, stderr=subprocess.PIPE,
            )
            time.sleep(duration)
            proc.terminate()
            proc.wait(timeout=5)

        _parse_zigbee_pcap(pcap_path, channel, devices)
    except Exception:
        pass
    finally:
        try:
            os.unlink(pcap_path)
        except OSError:
            pass

    return list(devices.values())


def _capture_zbdump(channel: int, duration: int,
                    devices: dict[str, ZigbeeDevice]) -> list[ZigbeeDevice]:
    """Capture using zbdump (scapy-based)."""
    import tempfile
    pcap_path = tempfile.mktemp(suffix=".pcap")

    try:
        proc = subprocess.Popen(
            ["zbdump", "-c", str(channel), "-w", pcap_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)

        _parse_zigbee_pcap(pcap_path, channel, devices)
    except Exception:
        pass
    finally:
        try:
            os.unlink(pcap_path)
        except OSError:
            pass

    return list(devices.values())


def _capture_ti_sniffer(channel: int, duration: int, device: str,
                        devices: dict[str, ZigbeeDevice]) -> list[ZigbeeDevice]:
    """Fallback: direct serial capture from CC2531."""
    if not device:
        return list(devices.values())

    try:
        import serial  # type: ignore[import-untyped]
    except ImportError:
        return list(devices.values())

    try:
        ser = serial.Serial(device, 115200, timeout=1)
        end_time = time.time() + duration
        raw_data = bytearray()

        while time.time() < end_time:
            chunk = ser.read(256)
            if chunk:
                raw_data.extend(chunk)
                _parse_zigbee_raw(raw_data, channel, devices)

        ser.close()
    except Exception:
        pass

    return list(devices.values())


def _parse_zigbee_pcap(pcap_path: str, channel: int,
                       devices: dict[str, ZigbeeDevice]) -> None:
    """Parse a PCAP file for Zigbee frames using tshark."""
    if not shutil.which("tshark"):
        return

    out, _, rc = _run([
        "tshark", "-r", pcap_path, "-T", "fields",
        "-e", "wpan.src16",
        "-e", "wpan.src64",
        "-e", "zbee_zcl.cluster_id",
        "-e", "zbee_nwk.src",
        "-e", "frame.len",
    ], timeout=30)

    if rc != 0:
        return

    for line in out.strip().splitlines():
        parts = line.split("\t")
        if len(parts) < 3:
            continue
        src16 = parts[0].strip()
        src64 = parts[1].strip() if len(parts) > 1 else ""
        cluster = parts[2].strip() if len(parts) > 2 else ""

        addr = src64 or src16
        if not addr:
            continue

        if addr not in devices:
            devices[addr] = ZigbeeDevice(
                short_addr=src16, ieee_addr=src64, channel=channel,
            )

        dev = devices[addr]
        dev.frame_count += 1

        if cluster:
            try:
                cid = int(cluster, 0)
                if cid in ZIGBEE_CAMERA_CLUSTERS:
                    desc = ZIGBEE_CAMERA_CLUSTERS[cid]
                    if desc not in dev.clusters:
                        dev.clusters.append(desc)
                    dev.suspicious = True
                    dev.reason = f"Camera/sensor cluster: {desc}"
            except ValueError:
                pass


def _parse_zigbee_raw(data: bytearray, channel: int,
                      devices: dict[str, ZigbeeDevice]) -> None:
    """Parse raw 802.15.4 frames from serial capture."""
    while len(data) >= 10:
        # Look for frame delimiter (0x00)
        if data[0] != 0x00:
            data.pop(0)
            continue

        if len(data) < 5:
            break

        frame_len = data[1]
        if len(data) < frame_len + 2:
            break

        frame = bytes(data[2:2 + frame_len])
        del data[:2 + frame_len]

        if len(frame) < 9:
            continue

        # Extract source address from 802.15.4 MAC header
        fcf = struct.unpack_from("<H", frame, 0)[0]
        src_mode = (fcf >> 14) & 0x3

        if src_mode == 2 and len(frame) >= 9:
            src16 = f"0x{struct.unpack_from('<H', frame, 7)[0]:04x}"
            if src16 not in devices:
                devices[src16] = ZigbeeDevice(short_addr=src16, channel=channel)
            devices[src16].frame_count += 1


# ---------------------------------------------------------------------------
# Z-Wave capture
# ---------------------------------------------------------------------------

def capture_zwave(duration: int = 60, device: str = "") -> list[ZwaveDevice]:
    """Capture Z-Wave traffic and identify devices."""
    devices: dict[int, ZwaveDevice] = {}

    if not device:
        device = find_zwave_stick() or ""

    if not device:
        return []

    if shutil.which("zwave-sniffer"):
        return _capture_zwave_sniffer(duration, device, devices)

    return list(devices.values())


def _capture_zwave_sniffer(duration: int, device: str,
                           devices: dict[int, ZwaveDevice]) -> list[ZwaveDevice]:
    """Capture Z-Wave frames using zwave-sniffer tool."""
    import tempfile
    pcap_path = tempfile.mktemp(suffix=".pcap")

    try:
        proc = subprocess.Popen(
            ["zwave-sniffer", "-d", device, "-o", pcap_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        time.sleep(duration)
        proc.terminate()
        proc.wait(timeout=5)

        if shutil.which("tshark"):
            out, _, rc = _run([
                "tshark", "-r", pcap_path, "-T", "fields",
                "-e", "zwave.src_node",
                "-e", "zwave.home_id",
                "-e", "zwave.cmd_class",
            ], timeout=30)

            if rc == 0:
                for line in out.strip().splitlines():
                    parts = line.split("\t")
                    if not parts[0]:
                        continue
                    try:
                        node_id = int(parts[0])
                    except ValueError:
                        continue

                    if node_id not in devices:
                        devices[node_id] = ZwaveDevice(node_id=node_id)

                    dev = devices[node_id]
                    dev.frame_count += 1
                    if len(parts) > 1:
                        dev.home_id = parts[1]
                    if len(parts) > 2 and parts[2]:
                        try:
                            cc = int(parts[2], 0)
                            if cc in ZWAVE_CAMERA_CLASSES:
                                desc = ZWAVE_CAMERA_CLASSES[cc]
                                if desc not in dev.command_classes:
                                    dev.command_classes.append(desc)
                                if cc in (0x30, 0x71, 0x84):
                                    dev.suspicious = True
                                    dev.reason = f"Sensor/notification class: {desc}"
                        except ValueError:
                            pass
    except Exception:
        pass
    finally:
        try:
            os.unlink(pcap_path)
        except OSError:
            pass

    return list(devices.values())


# ---------------------------------------------------------------------------
# Combined scan
# ---------------------------------------------------------------------------

def scan_zigbee_zwave(
    zigbee_channels: list[int] | None = None,
    zwave: bool = False,
    duration: int = 60,
) -> tuple[list[ZigbeeDevice], list[ZwaveDevice]]:
    """Scan for Zigbee and Z-Wave devices. Returns (zigbee_devices, zwave_devices)."""
    if zigbee_channels is None:
        zigbee_channels = [11, 15, 20, 25]

    zb_devices: list[ZigbeeDevice] = []
    zw_devices: list[ZwaveDevice] = []

    # Zigbee: scan popular channels
    cc2531 = find_cc2531()
    if cc2531:
        per_channel = max(duration // len(zigbee_channels), 10)
        for ch in zigbee_channels:
            zb_devices.extend(capture_zigbee(ch, per_channel, cc2531))

    # Z-Wave
    if zwave:
        zw_devices = capture_zwave(duration)

    # De-duplicate by address
    seen_zb: dict[str, ZigbeeDevice] = {}
    for d in zb_devices:
        key = d.ieee_addr or d.short_addr
        if key in seen_zb:
            seen_zb[key].frame_count += d.frame_count
            if d.suspicious:
                seen_zb[key].suspicious = True
                seen_zb[key].reason = d.reason
        else:
            seen_zb[key] = d

    return list(seen_zb.values()), zw_devices


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Zigbee/Z-Wave surveillance device sniffer")
    parser.add_argument("--channel", type=int, default=0,
                        help="Specific Zigbee channel (11-26); 0 = scan popular channels")
    parser.add_argument("--zwave", action="store_true", help="Also scan Z-Wave")
    parser.add_argument("--duration", type=int, default=60, help="Capture duration in seconds")
    args = parser.parse_args()

    channels = [args.channel] if args.channel else None

    print(f"\n  Zigbee/Z-Wave Sniffer")
    print(f"  {'=' * 40}")

    cc2531 = find_cc2531()
    zwave_dev = find_zwave_stick() if args.zwave else None
    print(f"  Zigbee dongle: {cc2531 or 'not found'}")
    if args.zwave:
        print(f"  Z-Wave stick:  {zwave_dev or 'not found'}")

    if not cc2531 and not zwave_dev:
        print("\n  No sniffer hardware found.")
        print("  Plug in a CC2531 dongle (Zigbee) or Z-Wave USB stick.")
        return

    print(f"  Listening for {args.duration}s...\n")
    zb, zw = scan_zigbee_zwave(channels, args.zwave, args.duration)

    if zb:
        print(f"  Found {len(zb)} Zigbee device(s):")
        for d in zb:
            flag = " ⚠️  SUSPICIOUS" if d.suspicious else ""
            addr = d.ieee_addr or d.short_addr
            print(f"    {addr}  ch{d.channel}  {d.frame_count} frames  {d.reason}{flag}")
            if d.clusters:
                print(f"      Clusters: {', '.join(d.clusters)}")
    else:
        print("  No Zigbee devices detected.")

    if zw:
        print(f"\n  Found {len(zw)} Z-Wave device(s):")
        for d in zw:
            flag = " ⚠️  SUSPICIOUS" if d.suspicious else ""
            print(f"    Node {d.node_id}  home={d.home_id}  {d.frame_count} frames{flag}")
            if d.command_classes:
                print(f"      Classes: {', '.join(d.command_classes)}")
    elif args.zwave:
        print("\n  No Z-Wave devices detected.")

    suspicious = [d for d in zb if d.suspicious] + [d for d in zw if d.suspicious]
    if suspicious:
        print(f"\n  ⚠️  {len(suspicious)} suspicious device(s) found!")
    else:
        print(f"\n  ✓ No suspicious devices detected.")
    print()


if __name__ == "__main__":
    main()
