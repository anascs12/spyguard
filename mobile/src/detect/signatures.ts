import sig from '@/data/signatures.json';

// Generated from the Python scanner: python3 scripts/export_signatures.py
const tier1 = sig.tier1Ouis as Record<string, string>;
const tier2 = sig.tier2Ouis as Record<string, string>;
const spyOuis = (sig as Record<string, unknown>).spyOuis as Record<string, string> | undefined;
const spyModelRaw = (sig as Record<string, unknown>).spyModelPattern as string | undefined;
const p2pPortsRaw = (sig as Record<string, unknown>).p2pPorts as number[] | undefined;
const spyPortCombosRaw = (sig as Record<string, unknown>).spyPortCombos as
  { ports: number[]; desc: string }[] | undefined;

export const CAMERA_PORTS: number[] = sig.cameraPorts;
export const RTSP_PORTS = new Set<number>(sig.rtspPorts);
export const HTTP_PORTS = new Set<number>(sig.httpPorts);
export const VENDOR_PORTS = new Set<number>(sig.vendorPorts);
export const WEAK_VENDOR_PORTS = new Set<number>(sig.weakVendorPorts);
export const RTSP_PATHS: string[] = sig.rtspPaths;
export const PHYSICAL_CHECKLIST: string[] = sig.physicalChecklist;

export const CAMERA_KEYWORDS_HIGH = new RegExp(sig.cameraKeywordsHigh, 'i');
export const CAMERA_HEADERS = new RegExp(sig.cameraHeaders, 'i');
export const CAMERA_TITLE = new RegExp(sig.cameraTitle, 'i');
export const CAMERA_MFR = new RegExp(sig.cameraMfrKeywords, 'i');
export const CAMERA_NAME_STRONG = new RegExp(sig.cameraNameStrong, 'i');
export const CAMERA_NAME_WEAK = new RegExp(sig.cameraNameWeak, 'i');
export const SPY_MODEL = spyModelRaw ? new RegExp(spyModelRaw, 'i') : null;
export const P2P_PORTS = new Set<number>(p2pPortsRaw ?? [32100, 34567, 34599, 9527, 8899, 32108, 20188, 6789]);
export const SPY_PORT_COMBOS = spyPortCombosRaw ?? [];

export function isRandomizedMac(mac: string): boolean {
  const first = parseInt(mac.replace(/[:-]/g, '').slice(0, 2), 16);
  return !Number.isNaN(first) && (first & 0x02) !== 0;
}

/** 1 surveillance brand, 2 consumer camera brand, 3 known spy device, 0 other, -1 randomized. */
export function ouiLookup(mac: string): { manufacturer: string; tier: number } {
  if (isRandomizedMac(mac)) return { manufacturer: '', tier: -1 };
  const oui = mac.toUpperCase().replace(/[:-]/g, '').slice(0, 6);
  if (spyOuis?.[oui]) return { manufacturer: spyOuis[oui], tier: 3 };
  if (tier1[oui]) return { manufacturer: tier1[oui], tier: 1 };
  if (tier2[oui]) return { manufacturer: tier2[oui], tier: 2 };
  return { manufacturer: '', tier: 0 };
}

export function matchSpyPortCombo(ports: number[]): string | null {
  const set = new Set(ports);
  for (const { ports: combo, desc } of SPY_PORT_COMBOS) {
    if (combo.every((p) => set.has(p))) return desc;
  }
  return null;
}

export function proximity(dbm: number | null | undefined): string {
  if (dbm == null) return 'signal unknown';
  if (dbm >= -55) return `${dbm} dBm · very close`;
  if (dbm >= -70) return `${dbm} dBm · nearby`;
  return `${dbm} dBm · far, likely a neighbour`;
}
