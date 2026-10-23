import { BleManager, type Device } from 'react-native-ble-plx';

import { base64ToBytes } from '@/lib/base64';

import { CAMERA_NAME_STRONG, CAMERA_NAME_WEAK, proximity } from './signatures';
import type { Finding, Risk } from './types';

let manager: BleManager | null = null;
function ble(): BleManager {
  manager ??= new BleManager();
  return manager;
}

export interface BleAdvert {
  id: string;
  name: string;
  rssi: number | null;
  /** company id -> payload (after the 2-byte id) */
  manufacturer: Map<number, Uint8Array>;
  services: Set<string>;
  serviceData: Map<string, Uint8Array>;
}

/** 16-bit form of a standard Bluetooth base UUID, else the full lowercase UUID. */
function uuid16(u: string): string {
  const l = u.toLowerCase();
  return l.length === 36 && l.endsWith('-0000-1000-8000-00805f9b34fb') ? l.slice(4, 8) : l;
}

function parse(d: Device): BleAdvert {
  const manufacturer = new Map<number, Uint8Array>();
  if (d.manufacturerData) {
    const b = base64ToBytes(d.manufacturerData);
    if (b.length >= 2) manufacturer.set(b[0] | (b[1] << 8), b.slice(2));
  }
  const serviceData = new Map<string, Uint8Array>();
  for (const [k, v] of Object.entries(d.serviceData ?? {})) {
    if (v) serviceData.set(uuid16(k), base64ToBytes(v));
  }
  return {
    id: d.id,
    name: d.localName ?? d.name ?? '',
    rssi: d.rssi,
    manufacturer,
    services: new Set((d.serviceUUIDs ?? []).map(uuid16)),
    serviceData,
  };
}

async function waitPoweredOn(): Promise<void> {
  const state = await ble().state();
  if (state === 'PoweredOn') return;
  if (state === 'Unsupported' || state === 'Unauthorized') throw new Error(`Bluetooth ${state.toLowerCase()}`);
  await new Promise<void>((resolve, reject) => {
    const t = setTimeout(() => (sub.remove(), reject(new Error('Turn Bluetooth on'))), 4000);
    const sub = ble().onStateChange((s) => {
      if (s === 'PoweredOn') {
        clearTimeout(t);
        sub.remove();
        resolve();
      }
    }, true);
  });
}

export async function scanBle(seconds = 12): Promise<BleAdvert[]> {
  await waitPoweredOn();
  const seen = new Map<string, BleAdvert>();
  await ble().startDeviceScan(null, { allowDuplicates: false }, (err, d) => {
    if (!err && d) seen.set(d.id, parse(d));
  });
  await new Promise((r) => setTimeout(r, seconds * 1000));
  await ble().stopDeviceScan();
  return [...seen.values()];
}

/** Live RSSI for one device until stop() is called. */
export async function watchBleRssi(id: string, onRssi: (dbm: number) => void): Promise<() => void> {
  await waitPoweredOn();
  await ble().startDeviceScan(null, { allowDuplicates: true }, (err, d) => {
    if (!err && d && d.id === id && d.rssi != null) onRssi(d.rssi);
  });
  return () => void ble().stopDeviceScan();
}

export function classifyBle(adverts: BleAdvert[]): Finding[] {
  const out: Finding[] = [];
  for (const a of adverts) {
    const close = a.rssi != null && a.rssi >= -70;
    const apple = a.manufacturer.get(0x004c);
    const fmdn = a.serviceData.get('feaa');
    const svcs = new Set([...a.services, ...a.serviceData.keys()]);
    let hit: [Risk, string, string] | null = null;

    // Find My offline beacon: 0x12, length 0x19 = separated from owner (0x02 = near owner).
    // Status bits 4-5: 0 Apple device, 1 AirTag, 2 Find My accessory, 3 AirPods.
    const appleType = apple && apple.length > 2 ? (apple[2] >> 4) & 0x3 : -1;
    if (apple && apple[0] === 0x12 && apple[1] === 0x19 && (appleType === 1 || appleType === 2)) {
      hit = [close ? 'HIGH' : 'LOW', appleType === 1 ? 'AirTag away from its owner' : 'Find My tracker away from its owner',
        'Broadcasting Apple’s “separated from owner” beacon'];
    } else if (fmdn && (fmdn[0] === 0x40 || fmdn[0] === 0x41)) {
      hit = [close ? 'HIGH' : 'LOW', 'Google Find My tracker', 'Broadcasting a Find My Device network beacon'];
    } else if (svcs.has('feed') || svcs.has('feec')) {
      hit = [close ? 'MODERATE' : 'LOW', 'Tile tracker', 'Advertising the Tile service'];
    } else if (svcs.has('fd5a')) {
      hit = [close ? 'MODERATE' : 'LOW', 'Samsung SmartTag', 'Advertising the SmartTag service'];
    } else if (svcs.has('fe33')) {
      hit = [close ? 'MODERATE' : 'LOW', 'Chipolo tracker', 'Advertising the Chipolo service'];
    } else if (a.name && CAMERA_NAME_STRONG.test(a.name)) {
      hit = ['HIGH', 'Bluetooth camera', `Camera-style name “${a.name}”. Bluetooth is used to set up cameras`];
    } else if (a.name && CAMERA_NAME_WEAK.test(a.name)) {
      hit = ['MODERATE', 'Camera-like Bluetooth name', `Name “${a.name}”`];
    }
    if (!hit) continue;
    const [risk, title, why] = hit;
    out.push({
      id: `ble:${a.id}`,
      risk,
      source: 'ble',
      address: a.id,
      title,
      manufacturer: a.name || 'Unknown',
      evidence: `${why} · ${proximity(a.rssi)}`,
      recommendation: 'Use Find to walk toward it. Trackers are often in bags, cars or furniture.',
      rssi: a.rssi,
    });
  }
  return out;
}
