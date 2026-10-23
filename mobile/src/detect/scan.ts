import { requestScanPermissions } from '@/lib/permissions';
import { getState, recordTimeline, setState } from '@/state/store';

import { classifyBle, scanBle } from './ble';
import { fetchLaptopResults } from './laptop';
import { networkInfo, scanLan } from './lan';
import type { Finding, Phase } from './types';
import { RISK_ORDER } from './types';
import { classifyUltrasound, scanUltrasound } from './ultrasound';
import { classifyAccessPoints, scanAccessPoints } from './wifi';

function updatePhase(key: Phase['key'], patch: Partial<Phase>): void {
  setState((s) => ({ phases: s.phases.map((p) => (p.key === key ? { ...p, ...patch } : p)) }));
}

function addFindings(found: Finding[]): void {
  setState((s) => {
    const byId = new Map(s.findings.map((f) => [f.id, f]));
    for (const f of found) byId.set(f.id, f);
    return { findings: sortFindings([...byId.values()]) };
  });
}

export function sortFindings(list: Finding[]): Finding[] {
  const rank = (f: Finding) => (f.trusted ? RISK_ORDER.length : RISK_ORDER.indexOf(f.risk));
  return [...list].sort((a, b) => rank(a) - rank(b) || (b.rssi ?? -200) - (a.rssi ?? -200));
}

async function phase(key: Phase['key'], run: () => Promise<{ found: Finding[]; detail: string }>): Promise<void> {
  updatePhase(key, { status: 'running', detail: undefined });
  try {
    const { found, detail } = await run();
    addFindings(found);
    updatePhase(key, { status: 'done', detail });
  } catch (e) {
    updatePhase(key, { status: 'error', detail: e instanceof Error ? e.message : String(e) });
  }
}

/** Run every detector the phone supports. Results stream into the store. */
export async function runScan(): Promise<void> {
  if (getState().scanning) return;
  const { laptop } = getState();
  setState({
    demo: false,
    scanning: true,
    progress: 0,
    findings: [],
    phases: [
      { key: 'lan', label: 'Your WiFi network', status: 'idle' },
      { key: 'wifi', label: 'Nearby WiFi networks', status: 'idle' },
      { key: 'ble', label: 'Bluetooth', status: 'idle' },
      { key: 'laptop', label: 'Laptop scanner', status: laptop ? 'idle' : 'skipped', detail: laptop ? undefined : 'Not linked' },
    ],
  });

  const perms = await requestScanPermissions();
  const net = networkInfo();
  const networkId = net ? `${net.gateway}/${net.prefixLength}` : 'unknown';

  // Radio scans run alongside the slower LAN sweep
  await Promise.all([
    phase('lan', async () => {
      if (!net) throw new Error('Not connected to WiFi');
      const found = await scanLan(net, (done, total) => {
        setState({ progress: done / total });
        updatePhase('lan', { detail: `${done} of ${total} addresses` });
      });
      return { found, detail: `${found.length} devices with open camera ports` };
    }),
    (async () => {
      await phase('wifi', async () => {
        if (!perms.wifi) throw new Error('Location / nearby-devices permission denied');
        const aps = await scanAccessPoints();
        const found = classifyAccessPoints(aps);
        return { found, detail: `${aps.length} networks · ${found.length} camera-like` };
      });
      await phase('ble', async () => {
        if (!perms.ble) throw new Error('Bluetooth permission denied');
        const adverts = await scanBle(12);
        const found = classifyBle(adverts);
        return { found, detail: `${adverts.length} devices · ${found.length} flagged` };
      });
      if (laptop) {
        await phase('laptop', async () => {
          const { findings, timestamp } = await fetchLaptopResults(laptop);
          const found = findings.filter((f) => f.risk !== 'INFO');
          return { found, detail: `Scan ${timestamp} · ${found.length} findings` };
        });
      }
    })(),
  ]);

  // Ultrasound scan (microphone-based, runs after radio scans)
  try {
    const usResult = await scanUltrasound();
    const usFindings = classifyUltrasound(usResult);
    if (usFindings.length > 0) addFindings(usFindings);
  } catch {
    // Microphone permission denied or unavailable
  }

  // Mark trusted and NEW (vs earlier scans on this network)
  setState((s) => {
    const seen = new Set(s.known[networkId] ?? []);
    const hadBaseline = seen.size > 0;
    const findings = s.findings.map((f) => ({
      ...f,
      trusted: !!s.trusted[f.id],
      isNew: f.isNew || (hadBaseline && !seen.has(f.id)),
    }));
    findings.forEach((f) => seen.add(f.id));
    return {
      findings: sortFindings(findings),
      known: { ...s.known, [networkId]: [...seen] },
      scanning: false,
      progress: 1,
      lastScan: Date.now(),
    };
  });

  // Record timeline snapshot for device presence tracking
  recordTimeline();
}
