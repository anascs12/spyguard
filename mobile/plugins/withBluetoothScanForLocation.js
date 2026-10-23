// react-native-ble-plx's library manifest declares BLUETOOTH_SCAN with
// usesPermissionFlags="neverForLocation", which makes Android filter BLE
// beacons out of scan results — including trackers this app must see.
// Replace the merged declaration with a plain one (location is granted anyway
// for WiFi scanning).
const { withAndroidManifest } = require('expo/config-plugins');

const SCAN = 'android.permission.BLUETOOTH_SCAN';

module.exports = function withBluetoothScanForLocation(config) {
  return withAndroidManifest(config, (cfg) => {
    const manifest = cfg.modResults.manifest;
    manifest.$['xmlns:tools'] ??= 'http://schemas.android.com/tools';
    const perms = (manifest['uses-permission'] ??= []);
    const existing = perms.find((p) => p.$['android:name'] === SCAN);
    const entry = existing ?? { $: { 'android:name': SCAN } };
    delete entry.$['android:usesPermissionFlags'];
    entry.$['tools:node'] = 'replace';
    if (!existing) perms.push(entry);
    return cfg;
  });
};
