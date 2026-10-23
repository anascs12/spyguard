import type { Finding, Phase } from '@/detect/types';

import { setState } from './store';

/**
 * Sample results for screenshots and UI review only. Opened with the link
 * privacyscanner://?demo=1 and always labelled "Demo data" in the app.
 */
const DEMO_FINDINGS: Finding[] = [
  {
    id: 'demo:lan:192.168.1.37', risk: 'CRITICAL', source: 'lan', address: '192.168.1.37', ip: '192.168.1.37',
    title: 'Video streaming device', manufacturer: 'Hipcam RealServer', ports: [80, 554],
    evidence: 'Answers the RTSP video protocol on port 554 (Hipcam RealServer); stream is password-protected',
    recommendation: 'Look for it physically. To track its signal, run the laptop scanner with --locate.',
  },
  {
    id: 'demo:wifi:C0:56:E3:4A:19:B2', risk: 'CRITICAL', source: 'wifi', address: 'C0:56:E3:4A:19:B2', rssi: -49,
    title: 'Camera hotspot', manufacturer: 'Hikvision', isNew: true,
    evidence: '“HAP-4A19B2” on channel 6 · -49 dBm · very close. Cameras broadcast their own WiFi in setup mode or for phone pairing.',
    recommendation: 'This is not your network. Use Find to walk toward the strongest signal.',
  },
  {
    id: 'demo:ble:F2:31:8C:07:5D:AA', risk: 'HIGH', source: 'ble', address: 'F2:31:8C:07:5D:AA', rssi: -58,
    title: 'AirTag away from its owner', manufacturer: 'Unknown',
    evidence: 'Broadcasting Apple’s “separated from owner” beacon · -58 dBm · nearby',
    recommendation: 'Use Find to walk toward it. Trackers are often in bags, cars or furniture.',
  },
  {
    id: 'demo:wifi:AA:41:07:9E:12:60', risk: 'HIGH', source: 'wifi', address: 'AA:41:07:9E:12:60', rssi: -66,
    title: 'Camera setup network', manufacturer: 'Unknown',
    evidence: '“V380-927341” on channel 11 · -66 dBm · nearby. Cameras broadcast their own WiFi in setup mode or for phone pairing.',
    recommendation: 'This is not your network. Use Find to walk toward the strongest signal.',
  },
  {
    id: 'demo:lan:192.168.1.52', risk: 'MODERATE', source: 'lan', address: '192.168.1.52', ip: '192.168.1.52',
    title: 'Possible camera port', manufacturer: 'Unknown', ports: [8000],
    evidence: 'Port used by Hikvision/Reolink cameras open (8000); also common on other devices',
    recommendation: 'Probably harmless. Check what it is if you can’t account for it.',
  },
  {
    id: 'demo:lan:192.168.1.20', risk: 'LOW', source: 'lan', address: '192.168.1.20', ip: '192.168.1.20',
    title: 'Device with web interface', manufacturer: 'lighttpd', ports: [80],
    evidence: 'Open ports 80 · Smart TV',
    recommendation: 'Probably harmless. Check what it is if you can’t account for it.',
  },
];

const DEMO_PHASES: Phase[] = [
  { key: 'lan', label: 'Your WiFi network', status: 'done', detail: '4 devices with open camera ports' },
  { key: 'wifi', label: 'Nearby WiFi networks', status: 'done', detail: '18 networks · 2 camera-like' },
  { key: 'ble', label: 'Bluetooth', status: 'done', detail: '31 devices · 1 flagged' },
  { key: 'laptop', label: 'Laptop scanner', status: 'skipped', detail: 'Not linked' },
];

export function loadDemo(): void {
  setState({
    demo: true,
    scanning: false,
    progress: 1,
    findings: DEMO_FINDINGS,
    phases: DEMO_PHASES,
    lastScan: Date.now(),
    locateTarget: null,
  });
}
