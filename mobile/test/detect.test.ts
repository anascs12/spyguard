/// <reference types="node" />
// Offline tests for the app's detection logic. Run: npm test
import assert from 'node:assert/strict';
import { test } from 'node:test';

import { classifyBle, type BleAdvert } from '../src/detect/ble';
import { classifyLanHost, hostsFor } from '../src/detect/lan';
import { parseLink } from '../src/detect/laptop';
import { detectSpots, SpotTracker } from '../src/detect/optical';
import { ouiLookup } from '../src/detect/signatures';
import { classifyAccessPoints } from '../src/detect/wifi';
import { base64ToBytes } from '../src/lib/base64';
import { latin1ToUtf8 } from '../src/lib/utf8';

const risks = (list: { address: string; risk: string }[]) =>
  Object.fromEntries(list.map((f) => [f.address, f.risk]));

test('shared signatures: OUI tiers from the Python scanner', () => {
  assert.deepEqual(ouiLookup('C0:56:E3:11:22:33'), { manufacturer: 'Hikvision', tier: 1 });
  assert.equal(ouiLookup('2C:AA:8E:00:00:00').tier, 2);
  assert.equal(ouiLookup('02:00:00:00:00:01').tier, -1);
});

test('nearby WiFi: camera hotspots flagged, ordinary names ignored', () => {
  const ap = (bssid: string, ssid: string, level = -60) => ({ bssid, ssid, level, frequency: 2437 });
  assert.deepEqual(risks(classifyAccessPoints([
    ap('AA:AA:AA:00:00:01', 'IPC-365821'),
    ap('C0:56:E3:00:00:02', 'HAP-1234'),
    ap('AA:AA:AA:00:00:03', "Camila's WiFi"),
    ap('AA:AA:AA:00:00:04', 'Living room cam'),
  ])), {
    'AA:AA:AA:00:00:01': 'HIGH',
    'C0:56:E3:00:00:02': 'CRITICAL',
    'AA:AA:AA:00:00:04': 'MODERATE',
  });
});

test('Bluetooth: separated trackers flagged, iPhones near owners ignored', () => {
  const adv = (id: string, extra: Partial<BleAdvert>): BleAdvert => ({
    id, name: '', rssi: -50, manufacturer: new Map(), services: new Set(), serviceData: new Map(), ...extra,
  });
  const apple = (bytes: number[]) => new Map([[0x004c, Uint8Array.from(bytes)]]);
  assert.deepEqual(risks(classifyBle([
    adv('airtag', { manufacturer: apple([0x12, 0x19, 0x10, ...Array(25).fill(0)]) }),
    adv('iphone-near', { manufacturer: apple([0x12, 0x02, 0x00, 0x02]) }),
    adv('iphone-offline', { manufacturer: apple([0x12, 0x19, 0x00, ...Array(25).fill(0)]) }),
    adv('far-airtag', { rssi: -90, manufacturer: apple([0x12, 0x19, 0x10, ...Array(25).fill(0)]) }),
    adv('tile', { services: new Set(['feed']) }),
    adv('cam', { name: 'V380_CAM' }),
    adv('speaker', { name: 'JBL Flip 5' }),
  ])), { airtag: 'HIGH', 'far-airtag': 'LOW', tile: 'MODERATE', cam: 'HIGH' });
});

test('LAN: RTSP and camera pages are critical, port 8000 alone is not', () => {
  const rtsp = { server: 'Hipcam', authRequired: true, openStream: '', port: 554 };
  const camPage = { server: 'App-webs/', title: 'NETSurveillance WEB', cameraHeader: true, cameraTitle: true, cameraKeywords: [] };
  const router = { server: 'lighttpd', title: 'Router', cameraHeader: false, cameraTitle: false, cameraKeywords: [] };
  assert.equal(classifyLanHost('10.0.0.5', [554], rtsp, [], '10.0.0.1').risk, 'CRITICAL');
  assert.equal(classifyLanHost('10.0.0.5', [554], { ...rtsp, openStream: '/live' }, [], '10.0.0.1').title, 'Live video stream, no password');
  assert.equal(classifyLanHost('10.0.0.6', [80], null, [camPage], '10.0.0.1').risk, 'CRITICAL');
  assert.equal(classifyLanHost('10.0.0.7', [8000], null, [], '10.0.0.1').risk, 'MODERATE');
  assert.equal(classifyLanHost('10.0.0.8', [37777], null, [], '10.0.0.1').risk, 'HIGH');
  assert.equal(classifyLanHost('10.0.0.1', [80], null, [router], '10.0.0.1').risk, 'INFO');
});

test('LAN: host list follows the real subnet, capped for huge networks', () => {
  assert.equal(hostsFor({ ip: '192.168.1.20', prefixLength: 24, gateway: '', interface: '' }).length, 253);
  assert.equal(hostsFor({ ip: '10.29.68.78', prefixLength: 22, gateway: '', interface: '' }).length, 1021);
  const big = hostsFor({ ip: '10.5.7.9', prefixLength: 16, gateway: '', interface: '' });
  assert.equal(big.length, 253);
  assert.equal(big[0], '10.5.7.1');
});

test('optical: a small isolated bright dot persists; a lit surface does not', () => {
  const w = 320, h = 240;
  const frame = () => {
    const px = new Uint8Array(w * h * 4);
    for (let i = 0; i < w * h; i++) px.set([12, 12, 14, 255], i * 4);
    const paint = (x0: number, y0: number, x1: number, y1: number) => {
      for (let y = y0; y <= y1; y++) for (let x = x0; x <= x1; x++) px.set([250, 245, 240, 255], (y * w + x) * 4);
    };
    paint(20, 20, 120, 90);     // lamp
    paint(200, 150, 202, 152);  // lens glint
    return px;
  };
  const tracker = new SpotTracker();
  let hits: ReturnType<typeof tracker.update> = [];
  for (let i = 0; i < 3; i++) hits = tracker.update(detectSpots(frame(), w, h));
  assert.equal(hits.length, 1);
  assert.ok(Math.abs(hits[0].x - 201 / w) < 0.01 && Math.abs(hits[0].y - 151 / h) < 0.01);
});

test('laptop link parsing and text helpers', () => {
  assert.deepEqual(parseLink('privacyscanner://link?host=10.0.0.4&port=8765&token=abc123'),
    { host: '10.0.0.4', port: 8765, token: 'abc123' });
  assert.equal(parseLink('https://example.com'), null);
  assert.deepEqual([...base64ToBytes('TACZ')], [0x4c, 0x00, 0x99]);
  assert.equal(latin1ToUtf8('cafÃ© â\u0080\u0094'), 'café —');
});
