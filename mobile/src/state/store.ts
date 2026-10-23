import AsyncStorage from '@react-native-async-storage/async-storage';
import { useSyncExternalStore } from 'react';

import type { LaptopLink } from '@/detect/laptop';
import type { Finding, Phase } from '@/detect/types';

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
}

const PERSISTED = ['trusted', 'known', 'laptop'] as const;
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
