import sig from '@/data/signatures.json';

// Generated from the Python scanner: python3 scripts/export_signatures.py
const tier1 = sig.tier1Ouis as Record<string, string>;
const tier2 = sig.tier2Ouis as Record<string, string>;

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

export function isRandomizedMac(mac: string): boolean {
  const first = parseInt(mac.replace(/[:-]/g, '').slice(0, 2), 16);
  return !Number.isNaN(first) && (first & 0x02) !== 0;
}

/** 1 surveillance brand, 2 consumer camera brand, 0 other, -1 randomized. */
export function ouiLookup(mac: string): { manufacturer: string; tier: number } {
  if (isRandomizedMac(mac)) return { manufacturer: '', tier: -1 };
  const oui = mac.toUpperCase().replace(/[:-]/g, '').slice(0, 6);
  if (tier1[oui]) return { manufacturer: tier1[oui], tier: 1 };
  if (tier2[oui]) return { manufacturer: tier2[oui], tier: 2 };
  return { manufacturer: '', tier: 0 };
}

export function proximity(dbm: number | null | undefined): string {
  if (dbm == null) return 'signal unknown';
  if (dbm >= -55) return `${dbm} dBm · very close`;
  if (dbm >= -70) return `${dbm} dBm · nearby`;
  return `${dbm} dBm · far, likely a neighbour`;
}
