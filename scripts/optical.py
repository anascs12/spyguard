#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""
Optical hidden-camera finder for privacy-scanner.

Finds cameras that never touch a network (powered off, SD-card only):

  - Lens glint: a camera lens reflects light straight back to its source.
    Sweep the room in the dark with a light right next to the recording
    camera; lenses show up as tiny, very bright points that stay put.
  - Infrared LEDs: night-vision cameras light the room with IR that phone
    front cameras and most webcams can see as white/purple dots.

Input is a live webcam (index, e.g. 0) or a video file recorded on a phone
with the flashlight on. Candidates are saved as annotated snapshots.
Needs OpenCV: pip install opencv-python
"""

from __future__ import annotations

import math
import time
from pathlib import Path

try:
    import cv2  # type: ignore
    import numpy as np  # type: ignore
    HAS_CV2 = True
except ImportError:
    HAS_CV2 = False


def _candidates(frame) -> list[tuple[int, int, float, str]]:
    """Return (x, y, score, kind) for small, bright, isolated, round points."""
    hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
    v = hsv[:, :, 2]
    scale = frame.shape[1] / 1280.0
    min_area, max_area = max(2, int(3 * scale * scale)), int(200 * scale * scale) + 4

    _, mask = cv2.threshold(v, 230, 255, cv2.THRESH_BINARY)
    contours, _ = cv2.findContours(mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
    scene = float(np.mean(v))
    found = []
    for c in contours:
        area = cv2.contourArea(c)
        if not min_area <= area <= max_area:
            continue
        perim = cv2.arcLength(c, True) or 1
        circularity = 4 * math.pi * area / (perim * perim)
        if circularity < 0.55:
            continue
        x, y, w, h = cv2.boundingRect(c)
        cx, cy = x + w // 2, y + h // 2
        pad = max(w, h) * 2 + 4
        ring = v[max(0, cy - pad):cy + pad, max(0, cx - pad):cx + pad]
        ring_mean = float(np.mean(ring))
        # A lens glint is a point, not part of a lit surface
        if ring_mean > 140:
            continue
        sat = float(np.mean(hsv[y:y + h, x:x + w, 1]))
        hue = float(np.mean(hsv[y:y + h, x:x + w, 0]))
        if scene < 40 and (sat < 60 or 125 <= hue <= 160):
            kind = "IR LED"  # dark room: IR shows as white or purple
        else:
            kind = "lens glint"
        found.append((cx, cy, (255 - ring_mean) * circularity, kind))
    return found


class _Tracker:
    """Keep only points that persist across frames (noise and sparkles don't)."""

    def __init__(self, radius: float, min_hits: int):
        self.radius = radius
        self.min_hits = min_hits
        self.tracks: list[dict] = []

    def update(self, points, frame_no: int) -> list[dict]:
        for x, y, score, kind in points:
            best = None
            for t in self.tracks:
                if frame_no - t["last"] <= 3 and math.hypot(t["x"] - x, t["y"] - y) <= self.radius:
                    best = t
                    break
            if best:
                best.update(x=x, y=y, last=frame_no, hits=best["hits"] + 1,
                            score=max(best["score"], score))
            else:
                self.tracks.append({"x": x, "y": y, "first": frame_no, "last": frame_no,
                                    "hits": 1, "score": score, "kind": kind, "saved": False})
        self.tracks = [t for t in self.tracks if frame_no - t["last"] <= 15]
        return [t for t in self.tracks if t["hits"] >= self.min_hits and t["last"] == frame_no]


def run(source: str, out_dir: Path, show: bool = True) -> list[dict]:
    """Analyse a webcam (digit) or video file. Returns saved detections."""
    if not HAS_CV2:
        print("  Optical mode needs OpenCV: pip install opencv-python")
        return []
    cap = cv2.VideoCapture(int(source) if source.isdigit() else source)
    if not cap.isOpened():
        print(f"  Could not open video source: {source}")
        return []

    live = source.isdigit()
    out_dir.mkdir(parents=True, exist_ok=True)
    print("\n  OPTICAL SWEEP")
    print("  1. Darken the room.  2. Hold a light right beside the camera.")
    print("  3. Sweep slowly across walls, shelves, smoke detectors, chargers, vents.")
    print("  Steady bright dots that stay on one object are candidates.")
    print("  " + ("Press q in the window (or Ctrl-C) to stop." if live else "Analysing video..."))

    tracker = None
    detections: list[dict] = []
    frame_no = 0
    window = show
    try:
        while True:
            ok, frame = cap.read()
            if not ok:
                break
            frame_no += 1
            if tracker is None:
                tracker = _Tracker(radius=frame.shape[1] / 40, min_hits=5)
            confirmed = tracker.update(_candidates(frame), frame_no)

            for t in confirmed:
                color = (0, 0, 255) if t["kind"] == "lens glint" else (255, 0, 255)
                cv2.circle(frame, (t["x"], t["y"]), 18, color, 2)
                cv2.putText(frame, t["kind"], (t["x"] + 20, t["y"]), cv2.FONT_HERSHEY_SIMPLEX,
                            0.5, color, 1)
            for t in confirmed:
                if not t["saved"]:
                    t["saved"] = True
                    path = out_dir / f"candidate-{len(detections) + 1:03d}-{t['kind'].replace(' ', '-')}.jpg"
                    cv2.imwrite(str(path), frame)
                    detections.append({"kind": t["kind"], "frame": frame_no,
                                       "x": t["x"], "y": t["y"], "snapshot": str(path)})
                    print(f"  [{t['kind']}] candidate at frame {frame_no} -> {path.name}", flush=True)

            if window:
                try:
                    cv2.imshow("privacy-scanner optical sweep", frame)
                    if cv2.waitKey(1) & 0xFF == ord("q"):
                        break
                except cv2.error:
                    window = False  # headless: keep analysing without a window
            elif live:
                time.sleep(0.01)
    except KeyboardInterrupt:
        pass
    finally:
        cap.release()
        if window:
            cv2.destroyAllWindows()

    print(f"\n  {len(detections)} candidate(s). Snapshots in {out_dir}")
    if detections:
        print("  Inspect each spot up close: shine a light from your eye level and look for a")
        print("  tiny round reflection. Glass, screws, water drops and LEDs can also trigger this.")
    return detections
