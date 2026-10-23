/**
 * Lens-glint / IR-LED detection on RGBA frames (port of scripts/optical.py).
 *
 * A camera lens reflects light straight back to its source, so with the
 * flashlight on it shows up as a tiny, very bright, isolated point that stays
 * on the same object across frames. Night-vision IR LEDs look similar in the dark.
 */

export interface Spot {
  /** 0..1 relative to frame width/height */
  x: number;
  y: number;
  kind: 'lens' | 'ir';
  score: number;
}

export function detectSpots(rgba: Uint8Array, width: number, height: number): Spot[] {
  const n = width * height;
  const v = new Uint8Array(n);
  let sum = 0;
  for (let i = 0, p = 0; i < n; i++, p += 4) {
    const m = Math.max(rgba[p], rgba[p + 1], rgba[p + 2]);
    v[i] = m;
    sum += m;
  }
  const scene = sum / n;
  const scale = width / 640;
  const minArea = Math.max(2, Math.round(3 * scale * scale));
  const maxArea = Math.round(160 * scale * scale) + 4;

  const label = new Int32Array(n);
  const stack: number[] = [];
  const spots: Spot[] = [];
  let next = 1;
  for (let start = 0; start < n; start++) {
    if (v[start] < 230 || label[start]) continue;
    // Flood-fill one bright blob
    let area = 0, minX = width, maxX = 0, minY = height, maxY = 0, sx = 0, sy = 0;
    let rs = 0, gs = 0, bs = 0;
    label[start] = next;
    stack.push(start);
    while (stack.length) {
      const i = stack.pop()!;
      const x = i % width, y = (i / width) | 0;
      area++;
      sx += x; sy += y;
      rs += rgba[i * 4]; gs += rgba[i * 4 + 1]; bs += rgba[i * 4 + 2];
      if (x < minX) minX = x; if (x > maxX) maxX = x;
      if (y < minY) minY = y; if (y > maxY) maxY = y;
      // Label the whole blob even when it's too big, or its remainder would
      // be picked up later as small "spots"
      for (const j of [i - 1, i + 1, i - width, i + width]) {
        if (j >= 0 && j < n && !label[j] && v[j] >= 230 && Math.abs((j % width) - x) <= 1) {
          label[j] = next;
          stack.push(j);
        }
      }
    }
    next++;
    if (area < minArea || area > maxArea) continue;
    const w = maxX - minX + 1, h = maxY - minY + 1;
    const fill = area / (w * h);
    if (fill < 0.45 || w > 2.5 * h || h > 2.5 * w) continue; // round-ish

    // Isolation: the ring around a glint is dark; a lit surface is not
    const cx = Math.round(sx / area), cy = Math.round(sy / area);
    const pad = Math.max(w, h) * 2 + 3;
    let ringSum = 0, ringN = 0;
    for (let y = Math.max(0, cy - pad); y <= Math.min(height - 1, cy + pad); y++) {
      for (let x = Math.max(0, cx - pad); x <= Math.min(width - 1, cx + pad); x++) {
        if (x >= minX && x <= maxX && y >= minY && y <= maxY) continue;
        ringSum += v[y * width + x];
        ringN++;
      }
    }
    const ring = ringN ? ringSum / ringN : 255;
    if (ring > 140) continue;

    const r = rs / area, g = gs / area, b = bs / area;
    const max = Math.max(r, g, b), min = Math.min(r, g, b);
    const sat = max ? (max - min) / max : 0;
    const purple = b > g && r > g;
    spots.push({
      x: cx / width,
      y: cy / height,
      kind: scene < 40 && (sat < 0.25 || purple) ? 'ir' : 'lens',
      score: (255 - ring) * fill,
    });
  }
  return spots;
}

interface Track extends Spot {
  hits: number;
  last: number;
}

/** Keep spots that persist across frames; sparkles and noise don't. */
export class SpotTracker {
  private tracks: Track[] = [];
  private frame = 0;
  private radius: number;
  private minHits: number;

  constructor(radius = 0.06, minHits = 3) {
    this.radius = radius;
    this.minHits = minHits;
  }

  update(spots: Spot[]): Spot[] {
    this.frame++;
    for (const s of spots) {
      const t = this.tracks.find(
        (k) => this.frame - k.last <= 2 && Math.hypot(k.x - s.x, k.y - s.y) <= this.radius,
      );
      if (t) Object.assign(t, { x: s.x, y: s.y, last: this.frame, hits: t.hits + 1, score: Math.max(t.score, s.score) });
      else this.tracks.push({ ...s, hits: 1, last: this.frame });
    }
    this.tracks = this.tracks.filter((t) => this.frame - t.last <= 4);
    return this.tracks.filter((t) => t.hits >= this.minHits && t.last === this.frame);
  }

  reset(): void {
    this.tracks = [];
  }
}
