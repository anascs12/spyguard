import { PrivacyNative, type WifiScanResult } from '@modules/privacy-native';

import { CAMERA_NAME_STRONG, CAMERA_NAME_WEAK, ouiLookup, proximity } from './signatures';
import type { Finding } from './types';

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** Nearby access points. Android throttles scans to ~4 per 2 minutes. */
export async function scanAccessPoints(): Promise<WifiScanResult[]> {
  if (!PrivacyNative) throw new Error('Needs the installed app (not Expo Go)');
  PrivacyNative.startWifiScan();
  await sleep(4000);
  return PrivacyNative.getWifiScanResults();
}

export function channelOf(freq: number): number {
  if (freq >= 2412 && freq <= 2484) return freq === 2484 ? 14 : (freq - 2407) / 5;
  if (freq >= 5000) return (freq - 5000) / 5;
  return 0;
}

export function classifyAccessPoints(aps: WifiScanResult[]): Finding[] {
  const out: Finding[] = [];
  for (const ap of aps) {
    const { manufacturer, tier } = ouiLookup(ap.bssid);
    const brand = tier === 1 || tier === 2;
    const strong = CAMERA_NAME_STRONG.test(ap.ssid);
    const weak = CAMERA_NAME_WEAK.test(ap.ssid);
    let risk: Finding['risk'];
    let title: string;
    if (brand && strong) [risk, title] = ['CRITICAL', 'Camera hotspot'];
    else if (brand) [risk, title] = ['HIGH', 'Camera-brand network'];
    else if (strong) [risk, title] = ['HIGH', 'Camera setup network'];
    else if (weak) [risk, title] = ['MODERATE', 'Camera-like network name'];
    else continue;
    out.push({
      id: `wifi:${ap.bssid}`,
      risk,
      source: 'wifi',
      address: ap.bssid.toUpperCase(),
      title,
      manufacturer: manufacturer || 'Unknown',
      evidence:
        `${ap.ssid ? `“${ap.ssid}”` : 'Hidden network'} on channel ${channelOf(ap.frequency)} · ` +
        `${proximity(ap.level)}. Cameras broadcast their own WiFi in setup mode or for phone pairing.`,
      recommendation: 'This is not your network. Use Find to walk toward the strongest signal.',
      rssi: ap.level,
    });
  }
  return out;
}

/** Latest RSSI for one BSSID, for the locator. */
export async function readAccessPointRssi(bssid: string): Promise<number | null> {
  const aps = await scanAccessPoints();
  return aps.find((a) => a.bssid.toUpperCase() === bssid.toUpperCase())?.level ?? null;
}
