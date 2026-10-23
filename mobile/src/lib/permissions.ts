import { PermissionsAndroid, Platform, type Permission } from 'react-native';

/** Location (WiFi scan results) + nearby devices (WiFi/Bluetooth on Android 12+). */
export async function requestScanPermissions(): Promise<{ wifi: boolean; ble: boolean }> {
  if (Platform.OS !== 'android') return { wifi: false, ble: true };
  const api = Number(Platform.Version);
  const P = PermissionsAndroid.PERMISSIONS;
  const wanted: Permission[] = [P.ACCESS_FINE_LOCATION];
  if (api >= 31) wanted.push(P.BLUETOOTH_SCAN, P.BLUETOOTH_CONNECT);
  if (api >= 33) wanted.push(P.NEARBY_WIFI_DEVICES);
  const res = await PermissionsAndroid.requestMultiple(wanted);
  const ok = (p: Permission) => res[p] === PermissionsAndroid.RESULTS.GRANTED;
  const location = ok(P.ACCESS_FINE_LOCATION);
  return {
    wifi: location && (api < 33 || ok(P.NEARBY_WIFI_DEVICES)),
    ble: api >= 31 ? ok(P.BLUETOOTH_SCAN) && ok(P.BLUETOOTH_CONNECT) : location,
  };
}
