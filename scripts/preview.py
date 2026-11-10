#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Camera's-eye view for privacy-scanner.

When the RTSP probe finds a stream that serves video to anyone on the
network without a password, save ONE still from it. Seeing what the camera
sees is the fastest way to work out where it is mounted, and the frame is
evidence that it was pointed at a private area.

Boundary: this module never authenticates. The URL carries no credentials,
a 401 is never answered, and it is only called for streams that
detectors.probe_rtsp() already marked as open. A password-protected camera
gets no preview: it is reported and left to the signal locator.

Needs ffmpeg or opencv-python. The frame may show you: it stays on this
computer (results folder, evidence pack, and the phone link if you use it).
"""

from __future__ import annotations

import base64
import hashlib
import shutil
import subprocess
import time
from pathlib import Path

try:
    import cv2  # type: ignore
    import numpy as np  # type: ignore
except ImportError:  # pragma: no cover
    cv2 = None

THUMB_WIDTH = 480
DATA_URI_PREFIX = "data:image/jpeg;base64,"


def available() -> bool:
    return bool(shutil.which("ffmpeg")) or cv2 is not None


def stream_url(ip: str, port: str, path: str) -> str:
    """rtsp:// URL for an open stream. Never carries a username or password."""
    return f"rtsp://{ip}:{port}{path}"


def _is_jpeg(data: bytes) -> bool:
    return data.startswith(b"\xff\xd8") and len(data) > 256


def _grab_ffmpeg(url: str, timeout: float) -> bytes | None:
    if not shutil.which("ffmpeg"):
        return None
    try:
        proc = subprocess.run(
            ["ffmpeg", "-nostdin", "-loglevel", "error", "-rtsp_transport", "tcp", "-i", url,
             "-frames:v", "1", "-f", "image2pipe", "-vcodec", "mjpeg", "-q:v", "3", "-"],
            capture_output=True, timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout if _is_jpeg(proc.stdout) else None


def _grab_cv2(url: str, timeout: float) -> bytes | None:
    if cv2 is None:
        return None
    ms = int(timeout * 1000)
    try:
        cap = cv2.VideoCapture(url, cv2.CAP_FFMPEG, [cv2.CAP_PROP_OPEN_TIMEOUT_MSEC, ms,
                                                     cv2.CAP_PROP_READ_TIMEOUT_MSEC, ms])
    except (cv2.error, TypeError):
        return None
    try:
        frame = None
        end = time.time() + timeout
        # The first frames after joining mid-stream are often incomplete
        for _ in range(5):
            ok, img = cap.read()
            if ok:
                frame = img
            if time.time() > end:
                break
        if frame is None:
            return None
        ok, buf = cv2.imencode(".jpg", frame, [cv2.IMWRITE_JPEG_QUALITY, 90])
        return buf.tobytes() if ok else None
    finally:
        cap.release()


def grab_frame(ip: str, port: str, path: str, timeout: float = 12.0) -> bytes | None:
    """One JPEG frame from an unauthenticated RTSP stream, or None."""
    url = stream_url(ip, port, path)
    return _grab_ffmpeg(url, timeout) or _grab_cv2(url, timeout)


def thumbnail(jpeg: bytes, width: int = THUMB_WIDTH) -> bytes:
    """Smaller copy for embedding in results.json and the HTML report."""
    if cv2 is not None:
        img = cv2.imdecode(np.frombuffer(jpeg, np.uint8), cv2.IMREAD_COLOR)
        if img is not None:
            h, w = img.shape[:2]
            if w > width:
                img = cv2.resize(img, (width, max(1, round(h * width / w))), interpolation=cv2.INTER_AREA)
            ok, buf = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 70])
            if ok:
                return buf.tobytes()
    if shutil.which("ffmpeg"):
        try:
            proc = subprocess.run(
                ["ffmpeg", "-nostdin", "-loglevel", "error", "-f", "image2pipe", "-i", "-",
                 "-vf", f"scale='min({width},iw)':-2", "-frames:v", "1",
                 "-f", "image2pipe", "-vcodec", "mjpeg", "-q:v", "6", "-"],
                input=jpeg, capture_output=True, timeout=15,
            )
            if _is_jpeg(proc.stdout):
                return proc.stdout
        except (OSError, subprocess.TimeoutExpired):
            pass
    return jpeg


def is_preview_uri(value: object) -> bool:
    """True for the exact data: URI shape this module writes (safe to put in an <img>)."""
    if not isinstance(value, str) or not value.startswith(DATA_URI_PREFIX):
        return False
    body = value[len(DATA_URI_PREFIX):]
    return bool(body) and all(c.isalnum() or c in "+/=" for c in body)


def capture(ip: str, port: str, path: str, out_dir: str | Path, timeout: float = 12.0) -> dict | None:
    """Save a still from an open stream into out_dir.

    Returns {file, sha256, captured, stream, data_uri} or None if no frame
    could be read. The full-size JPEG lands in out_dir, so it is included
    in the evidence pack with its own hash.
    """
    jpeg = grab_frame(ip, port, path, timeout)
    if not jpeg:
        return None
    name = f"camera-view-{ip.replace(':', '-')}.jpg"
    (Path(out_dir) / name).write_bytes(jpeg)
    return {
        "file": name,
        "sha256": hashlib.sha256(jpeg).hexdigest(),
        "captured": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "stream": stream_url(ip, port, path),
        "data_uri": DATA_URI_PREFIX + base64.b64encode(thumbnail(jpeg)).decode("ascii"),
    }
