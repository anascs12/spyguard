export type Risk = 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'INFO';

export const RISK_ORDER: Risk[] = ['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'INFO'];

/** Where a finding came from. Locatable sources carry an RSSI we can track. */
export type Source = 'lan' | 'wifi' | 'ble' | 'laptop' | 'ultrasound';

export interface Finding {
  id: string;
  risk: Risk;
  source: Source;
  /** MAC, BSSID, BLE id or IP: whatever identifies it for this source */
  address: string;
  ip?: string;
  title: string;
  manufacturer: string;
  evidence: string;
  recommendation: string;
  ports?: number[];
  rssi?: number | null;
  isNew?: boolean;
  trusted?: boolean;
}

export type PhaseStatus = 'idle' | 'running' | 'done' | 'skipped' | 'error';

export interface Phase {
  key: 'lan' | 'wifi' | 'ble' | 'laptop';
  label: string;
  status: PhaseStatus;
  detail?: string;
}
