import AsyncStorage from '@react-native-async-storage/async-storage';
import { useSyncExternalStore } from 'react';

import type { LaptopLink } from '@/detect/laptop';
import type { Finding, Phase } from '@/detect/types';

export interface RoomScan {
  room: string;
  timestamp: number;
  findingIds: string[];
}

export interface ScheduledScan {
  enabled: boolean;
  intervalMinutes: number;
  nextRun: number | null;
}

export interface TimelineEntry {
  timestamp: number;
  deviceIds: string[];
}

export interface DeviceTimeline {
  firstSeen: number;
  lastSeen: number;
  seenCount: number;
  windows: { start: number; end: number }[];
}

export interface AppState {
  scanning: boolean;
  /** showing sample data (privacyscanner://?demo=1) */
  demo: boolean;
  progress: number;
  phases: Phase[];
  findings: Finding[];
  lastScan: number | null;
  /** ids the user marked as their own devices */
  trusted: Record<string, string>;
  /** network id -> ids seen on earlier scans */
  known: Record<string, string[]>;
  laptop: LaptopLink | null;
  locateTarget: Finding | null;
  /** Multi-room comparison */
  rooms: RoomScan[];
  /** Scheduled background scans */
  schedule: ScheduledScan;
  /** Device timeline for presence tracking */
  timeline: TimelineEntry[];
  deviceTimelines: Record<string, DeviceTimeline>;
}

const PERSISTED = ['trusted', 'known', 'laptop', 'rooms', 'schedule', 'timeline', 'deviceTimelines'] as const;
const KEY = 'privacy-scanner/v1';

let state: AppState = {
  scanning: false,
  demo: false,
  progress: 0,
  phases: [],
  findings: [],
  lastScan: null,
  trusted: {},
  known: {},
  laptop: null,
  locateTarget: null,
  rooms: [],
  schedule: { enabled: false, intervalMinutes: 60, nextRun: null },
  timeline: [],
  deviceTimelines: {},
};
const listeners = new Set<() => void>();

export function getState(): AppState {
  return state;
}

export function setState(patch: Partial<AppState> | ((s: AppState) => Partial<AppState>)): void {
  const next = typeof patch === 'function' ? patch(state) : patch;
  state = { ...state, ...next };
  listeners.forEach((l) => l());
  if (PERSISTED.some((k) => k in next)) {
    const saved = Object.fromEntries(PERSISTED.map((k) => [k, state[k]]));
    AsyncStorage.setItem(KEY, JSON.stringify(saved)).catch(() => {});
  }
}

export function useStore<T>(select: (s: AppState) => T): T {
  return useSyncExternalStore(
    (l) => (listeners.add(l), () => listeners.delete(l)),
    () => select(state),
  );
}

export async function hydrate(): Promise<void> {
  try {
    const raw = await AsyncStorage.getItem(KEY);
    if (raw) setState(JSON.parse(raw));
  } catch {
    // First launch or corrupted storage: start fresh
  }
}

export function toggleTrusted(f: Finding): void {
  setState((s) => {
    const trusted = { ...s.trusted };
    if (trusted[f.id]) delete trusted[f.id];
    else trusted[f.id] = f.title;
    return {
      trusted,
      findings: s.findings.map((x) => (x.id === f.id ? { ...x, trusted: !!trusted[f.id] } : x)),
    };
  });
}

export function saveRoomScan(room: string): void {
  setState((s) => {
    const existing = s.rooms.filter((r) => r.room !== room);
    return {
      rooms: [
        ...existing,
        { room, timestamp: Date.now(), findingIds: s.findings.map((f) => f.id) },
      ],
    };
  });
}

export function recordTimeline(): void {
  const s = getState();
  const now = Date.now();
  const deviceIds = s.findings.map((f) => f.id);

  const entry: TimelineEntry = { timestamp: now, deviceIds };

  const deviceTimelines = { ...s.deviceTimelines };
  for (const id of deviceIds) {
    const existing = deviceTimelines[id];
    if (!existing) {
      deviceTimelines[id] = {
        firstSeen: now, lastSeen: now, seenCount: 1,
        windows: [{ start: now, end: now }],
      };
    } else {
      existing.lastSeen = now;
      existing.seenCount += 1;
      const lastWindow = existing.windows[existing.windows.length - 1];
      if (lastWindow && now - lastWindow.end < 30 * 60 * 1000) {
        lastWindow.end = now;
      } else {
        existing.windows.push({ start: now, end: now });
      }
      deviceTimelines[id] = { ...existing };
    }
  }

  setState({ timeline: [...s.timeline, entry], deviceTimelines });
}

export function getSuspiciousDevices(): { id: string; reasons: string[] }[] {
  const s = getState();
  const results: { id: string; reasons: string[] }[] = [];
  const totalSnapshots = s.timeline.length;
  if (totalSnapshots < 3) return [];

  for (const [id, tl] of Object.entries(s.deviceTimelines)) {
    const reasons: string[] = [];
    const ratio = tl.seenCount / totalSnapshots;
    if (ratio > 0.1 && ratio < 0.7) {
      reasons.push(`Intermittent: ${tl.seenCount}/${totalSnapshots} scans (${Math.round(ratio * 100)}%)`);
    }
    if (tl.windows.length >= 3) {
      reasons.push(`Turns on/off: ${tl.windows.length} separate windows`);
    }
    const firstIds = new Set(s.timeline[0]?.deviceIds ?? []);
    if (!firstIds.has(id) && tl.seenCount > 1) {
      reasons.push('Appeared after initial scan');
    }
    // Night-only pattern
    let nightCount = 0;
    let dayCount = 0;
    for (const w of tl.windows) {
      const hour = new Date(w.start).getHours();
      if (hour >= 22 || hour <= 6) nightCount++;
      else dayCount++;
    }
    if (nightCount >= 2 && dayCount === 0) {
      reasons.push(`Night-only: seen only 10 PM – 6 AM`);
    }
    if (reasons.length > 0) results.push({ id, reasons });
  }

  return results.sort((a, b) => b.reasons.length - a.reasons.length);
}

export function compareRooms(): { id: string; onlyIn: string }[] {
  const s = getState();
  if (s.rooms.length < 2) return [];
  const idRooms: Record<string, Set<string>> = {};
  for (const room of s.rooms) {
    for (const id of room.findingIds) {
      (idRooms[id] ??= new Set()).add(room.room);
    }
  }
  return Object.entries(idRooms)
    .filter(([, rooms]) => rooms.size === 1)
    .map(([id, rooms]) => ({ id, onlyIn: [...rooms][0] }));
}
