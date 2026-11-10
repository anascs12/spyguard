import { requireOptionalNativeModule } from 'expo-modules-core';

export interface NetworkInfo {
  ip: string;
  prefixLength: number;
  gateway: string;
  interface: string;
}

export interface WifiScanResult {
  bssid: string;
  ssid: string;
  /** dBm */
  level: number;
  /** MHz */
  frequency: number;
}

interface PrivacyNativeModule {
  getNetworkInfo(): NetworkInfo | null;
  startWifiScan(): boolean;
  getWifiScanResults(): WifiScanResult[];
  probePorts(hosts: string[], ports: number[], timeoutMs: number, concurrency: number): Promise<{ host: string; port: number }[]>;
  tcpExchange(host: string, port: number, payload: string, timeoutMs: number, maxBytes: number, untilClose: boolean): Promise<string | null>;
  /** One JPEG frame (data: URI) from an unauthenticated RTSP stream, or null. Never sends credentials. */
  grabRtspFrame(host: string, port: number, path: string, timeoutMs: number): Promise<string | null>;
}

/** Null in Expo Go or on iOS: callers must degrade gracefully. */
export const PrivacyNative = requireOptionalNativeModule<PrivacyNativeModule>('PrivacyNative');
