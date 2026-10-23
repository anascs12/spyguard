# Privacy Scanner — Android app

Detects hidden cameras and trackers from your phone. Built with Expo (React Native, TypeScript).

| Tab | What it does |
|---|---|
| **Scan** | One tap checks your WiFi network (real RTSP handshake, camera web pages, camera ports), nearby WiFi networks (camera setup hotspots, camera-brand access points) and Bluetooth (AirTag / Find My, Tile, SmartTag, Chipolo, Bluetooth cameras). Pulls in laptop results when linked. |
| **Find** | Hot/cold signal meter with Geiger-style vibration to walk to a flagged WiFi or Bluetooth device. |
| **Lens** | Flashlight + red filter + automatic lens-glint / infrared-LED detection. Finds cameras that are **offline or switched off**. |
| **Magnet** | Magnetometer sweep that picks up camera electronics a few centimetres away, even when powered off. |
| **Settings** | Laptop link (QR), trusted devices, per-network history (new devices show as **NEW**). |

Everything is detection-only: the app never logs into devices or joins other networks.

## Build and install (Android)

The app uses native code (Bluetooth, WiFi scanning, sockets), so it runs as a development or release
build, not in Expo Go.

**Option A: build in the cloud (no Android SDK needed)**
```bash
cd mobile
npm install
npx eas-cli@latest login
npx eas-cli@latest build -p android --profile preview   # gives you an .apk link to install
```

**Option B: build locally** (needs Android Studio / the Android SDK and a phone with USB debugging)
```bash
cd mobile
npm install
npx expo run:android            # builds, installs on the connected phone, starts the dev server
```

## Link the laptop scanner

The laptop adds what a phone can't do, such as monitor mode, which sees cameras talking on *other* WiFi networks.

```bash
sudo python3 scripts/scan.py --serve          # prints a QR code (pip install qrcode) and a link
```
In the app: **Settings → Laptop scanner → Scan QR**. Each phone scan then includes the laptop's latest results.

## Development

```bash
npm test              # detection logic tests (Node test runner, no device needed)
npm run typecheck
npm run lint
npm run signatures    # regenerate src/data/signatures.json from the Python scanner
```

- Camera brands, ports and name patterns come from `scripts/scan.py` via `scripts/export_signatures.py`,
  so the app and the laptop scanner always agree. Don't edit `src/data/signatures.json` by hand.
- Native Android code lives in `modules/privacy-native` (Expo Modules API, Kotlin): WiFi scan results,
  network info, parallel port probing and raw TCP exchange.

## What a phone can't detect

- Devices talking on other WiFi networks (Android doesn't allow monitor mode without root; use the laptop)
- MAC addresses of devices on your network (blocked since Android 10), so LAN results rely on ports and fingerprints
- Wired-only, 4G and audio-only devices
