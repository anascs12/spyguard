import { PrivacyNative } from '@modules/privacy-native';

import { latin1ToUtf8 } from '@/lib/utf8';

import type { Finding, Risk } from './types';

export interface LaptopLink {
  host: string;
  port: number;
  token: string;
}

/** Parse "privacyscanner://link?host=..&port=..&token=.." (shown by scan.py --serve). */
export function parseLink(text: string): LaptopLink | null {
  const m = /^privacyscanner:\/\/link\?(.+)$/.exec(text.trim());
  if (!m) return null;
  const q = Object.fromEntries(m[1].split('&').map((kv) => kv.split('=').map(decodeURIComponent)));
  const port = Number(q.port);
  return q.host && q.token && port ? { host: q.host, port, token: q.token } : null;
}

interface LaptopDevice {
  risk: Risk;
  ip: string;
  mac: string;
  manufacturer: string;
  device_type: string;
  open_ports: string;
  evidence: string;
  recommendation: string;
  source?: string;
  new?: boolean;
}

/** Pull results from the laptop scanner over the local network. */
export async function fetchLaptopResults(link: LaptopLink): Promise<{ findings: Finding[]; timestamp: string }> {
  if (!PrivacyNative) throw new Error('Needs the installed app (not Expo Go)');
  const resp = await PrivacyNative.tcpExchange(link.host, link.port,
    `GET /results.json?token=${encodeURIComponent(link.token)} HTTP/1.0\r\nHost: ${link.host}\r\n\r\n`,
    5000, 2_000_000, true);
  if (!resp) throw new Error('Laptop not reachable. Same WiFi? Is scan.py --serve running?');
  const statusLine = resp.slice(0, resp.indexOf('\r\n'));
  if (!/ 200 /.test(statusLine)) throw new Error(statusLine.includes('403') ? 'Wrong token' : statusLine);
  // Body is UTF-8 sent over a latin-1 transport: re-decode
  const raw = resp.slice(resp.indexOf('\r\n\r\n') + 4);
  const data = JSON.parse(latin1ToUtf8(raw)) as { timestamp: string; devices: LaptopDevice[] };
  return {
    timestamp: data.timestamp,
    findings: data.devices.map((d, i) => ({
      id: `laptop:${d.mac || d.ip}:${i}`,
      risk: d.risk,
      source: 'laptop',
      address: d.mac || d.ip,
      ip: d.ip,
      title: d.device_type,
      manufacturer: d.manufacturer || 'Unknown',
      evidence: `Laptop scan (${d.source ?? 'lan'}): ${d.evidence}`,
      recommendation: d.recommendation,
      ports: d.open_ports ? d.open_ports.split(',').map(Number) : undefined,
      isNew: d.new,
    })),
  };
}
