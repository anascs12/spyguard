import { PrivacyNative, type NetworkInfo } from '@modules/privacy-native';

import {
  CAMERA_HEADERS, CAMERA_KEYWORDS_HIGH, CAMERA_PORTS, CAMERA_TITLE, HTTP_PORTS,
  RTSP_PATHS, RTSP_PORTS, VENDOR_PORTS, WEAK_VENDOR_PORTS,
} from './signatures';
import type { Finding, Risk } from './types';

// Highest-signal ports, used when the subnet is too big for the full list
const QUICK_PORTS = [554, 8554, 80, 8080, 8000, 37777, 34567, 34599, 9000, 8899];

function ipToInt(ip: string): number {
  return ip.split('.').reduce((n, o) => (n << 8) + Number(o), 0) >>> 0;
}
function intToIp(n: number): string {
  return [24, 16, 8, 0].map((s) => (n >>> s) & 255).join('.');
}

/** Host addresses to probe. Subnets larger than /22 are narrowed to the phone's /24. */
export function hostsFor(info: NetworkInfo): string[] {
  const prefix = info.prefixLength < 22 ? 24 : Math.min(info.prefixLength, 30);
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  const net = ipToInt(info.ip) & mask;
  const count = 2 ** (32 - prefix);
  const hosts: string[] = [];
  for (let i = 1; i < count - 1; i++) {
    const ip = intToIp(net + i);
    if (ip !== info.ip) hosts.push(ip);
  }
  return hosts;
}

export function networkInfo(): NetworkInfo | null {
  return PrivacyNative?.getNetworkInfo() ?? null;
}

export interface RtspResult {
  server: string;
  authRequired: boolean;
  openStream: string;
}

const header = (resp: string, name: string) =>
  new RegExp(`^${name}:\\s*(.+?)\\s*$`, 'im').exec(resp)?.[1] ?? '';
const status = (resp: string) => Number(/^RTSP\/1\.\d\s+(\d{3})/.exec(resp)?.[1] ?? 0);

/** Real RTSP handshake: OPTIONS, then DESCRIBE on common paths. No credentials, no media. */
export async function probeRtsp(ip: string, port: number): Promise<RtspResult | null> {
  const ex = (method: string, path: string, cseq: number) =>
    PrivacyNative!.tcpExchange(ip, port,
      `${method} rtsp://${ip}:${port}${path} RTSP/1.0\r\nCSeq: ${cseq}\r\nUser-Agent: privacy-scanner\r\n` +
      (method === 'DESCRIBE' ? 'Accept: application/sdp\r\n' : '') + '\r\n', 3000, 16384, false);
  const opts = await ex('OPTIONS', '/', 1);
  if (!opts?.startsWith('RTSP/1.')) return null;
  const res: RtspResult = { server: header(opts, 'Server'), authRequired: false, openStream: '' };
  for (let i = 0; i < RTSP_PATHS.length; i++) {
    const d = (await ex('DESCRIBE', RTSP_PATHS[i], i + 2)) ?? '';
    if (status(d) === 200 && d.includes('m=video')) {
      res.openStream = RTSP_PATHS[i];
      break;
    }
    if (status(d) === 401) {
      res.authRequired = true;
      break;
    }
  }
  return res;
}

export interface HttpResult {
  server: string;
  title: string;
  cameraHeader: boolean;
  cameraTitle: boolean;
  cameraKeywords: string[];
}

/** HTTP/1.0 over a raw socket: no chunking, and not subject to Android's cleartext block. */
export async function probeHttp(ip: string, port: number): Promise<HttpResult | null> {
  const resp = await PrivacyNative!.tcpExchange(ip, port,
    `GET / HTTP/1.0\r\nHost: ${ip}\r\nUser-Agent: privacy-scanner\r\nConnection: close\r\n\r\n`,
    4000, 51200, true);
  if (!resp?.startsWith('HTTP/')) return null;
  const split = resp.indexOf('\r\n\r\n');
  const head = split >= 0 ? resp.slice(0, split) : resp;
  const body = split >= 0 ? resp.slice(split + 4) : '';
  const title = /<title>([^<]+)<\/title>/i.exec(body)?.[1]?.trim() ?? '';
  const keywords = [...new Set((body.match(new RegExp(CAMERA_KEYWORDS_HIGH.source, 'gi')) ?? []).map((k) => k.toLowerCase()))];
  return {
    server: header(head, 'Server'),
    title,
    cameraHeader: CAMERA_HEADERS.test(head),
    cameraTitle: !!title && CAMERA_TITLE.test(title),
    cameraKeywords: keywords.slice(0, 5),
  };
}

export async function scanLan(
  info: NetworkInfo,
  onProgress: (done: number, total: number) => void,
): Promise<Finding[]> {
  if (!PrivacyNative) throw new Error('Needs the installed app (not Expo Go)');
  const hosts = hostsFor(info);
  const ports = hosts.length > 254 ? QUICK_PORTS : CAMERA_PORTS;
  const open = new Map<string, number[]>();
  const chunk = 32;
  for (let i = 0; i < hosts.length; i += chunk) {
    const batch = await PrivacyNative.probePorts(hosts.slice(i, i + chunk), ports, 700, 128);
    for (const { host, port } of batch) open.set(host, [...(open.get(host) ?? []), port].sort((a, b) => a - b));
    onProgress(Math.min(i + chunk, hosts.length), hosts.length);
  }

  const findings: Finding[] = [];
  for (const [ip, openPorts] of open) {
    const rtspPorts = openPorts.filter((p) => RTSP_PORTS.has(p));
    const httpPorts = openPorts.filter((p) => HTTP_PORTS.has(p) && p !== 443 && p !== 8443);
    let rtsp: (RtspResult & { port: number }) | null = null;
    for (const p of rtspPorts) {
      const r = await probeRtsp(ip, p);
      if (r) {
        rtsp = { ...r, port: p };
        break;
      }
    }
    const http: HttpResult[] = [];
    for (const p of httpPorts) {
      const h = await probeHttp(ip, p);
      if (h) http.push(h);
    }
    findings.push(classifyLanHost(ip, openPorts, rtsp, http, info.gateway));
  }
  return findings;
}

export function classifyLanHost(
  ip: string,
  ports: number[],
  rtsp: (RtspResult & { port: number }) | null,
  http: HttpResult[],
  gateway: string,
): Finding {
  const camHttp = http.find((h) => h.cameraHeader || h.cameraTitle || h.cameraKeywords.length);
  const titles = http.map((h) => h.title || h.server).filter(Boolean);
  const hasVendor = ports.some((p) => VENDOR_PORTS.has(p));
  const hasWeak = ports.some((p) => WEAK_VENDOR_PORTS.has(p));
  const portList = ports.join(', ');
  let risk: Risk;
  let title: string;
  let evidence: string;

  if (rtsp?.openStream) {
    [risk, title] = ['CRITICAL', 'Live video stream, no password'];
    evidence = `RTSP ${rtsp.server} on port ${rtsp.port} serves video at ${rtsp.openStream} without a password`;
  } else if (rtsp) {
    [risk, title] = ['CRITICAL', 'Video streaming device'];
    evidence = `Answers the RTSP video protocol on port ${rtsp.port}${rtsp.server ? ` (${rtsp.server})` : ''}` +
      (rtsp.authRequired ? '; stream is password-protected' : '');
  } else if (camHttp) {
    [risk, title] = ['CRITICAL', 'Camera web interface'];
    evidence = [camHttp.title && `Page title “${camHttp.title}”`, camHttp.cameraHeader && `server ${camHttp.server}`,
      camHttp.cameraKeywords.length && `keywords: ${camHttp.cameraKeywords.join(', ')}`].filter(Boolean).join(' · ');
  } else if (hasVendor) {
    [risk, title] = ['HIGH', 'Camera protocol port open'];
    evidence = `Proprietary camera/NVR port open (${portList})`;
  } else if (ports.some((p) => RTSP_PORTS.has(p))) {
    [risk, title] = ['HIGH', 'Streaming port open'];
    evidence = `RTSP port open (${portList}) but the handshake didn’t complete`;
  } else if (ip === gateway) {
    [risk, title] = ['INFO', 'Your router'];
    evidence = `Network gateway${titles.length ? ` · ${titles.join(', ')}` : ''}`;
  } else if (hasWeak) {
    [risk, title] = ['MODERATE', 'Possible camera port'];
    evidence = `Port used by Hikvision/Reolink cameras open (${portList}); also common on other devices`;
  } else {
    [risk, title] = ['LOW', 'Device with web interface'];
    evidence = `Open ports ${portList}${titles.length ? ` · ${titles.join(', ')}` : ''}`;
  }

  return {
    id: `lan:${ip}`,
    risk,
    source: 'lan',
    address: ip,
    ip,
    title,
    manufacturer: http[0]?.server || 'Unknown',
    evidence,
    recommendation: risk === 'CRITICAL' || risk === 'HIGH'
      ? 'Look for it physically. To track its signal, run the laptop scanner with --locate.'
      : 'Probably harmless. Check what it is if you can’t account for it.',
    ports,
  };
}
