import { CameraView, useCameraPermissions } from 'expo-camera';
import * as Haptics from 'expo-haptics';
import { useIsFocused } from 'expo-router';
import { decode } from 'jpeg-js';
import { useCallback, useEffect, useRef, useState } from 'react';
import { Pressable, StyleSheet, Text, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { detectSpots, SpotTracker, type Spot } from '@/detect/optical';
import { base64ToBytes } from '@/lib/base64';
import { Button, EmptyState, Icon, Screen } from '@/ui/components';
import { radius, riskColors, space, type, usePalette } from '@/ui/theme';

export default function LensScreen() {
  const c = usePalette();
  const insets = useSafeAreaInsets();
  const focused = useIsFocused();
  const [permission, requestPermission] = useCameraPermissions();
  const camera = useRef<CameraView>(null);
  const tracker = useRef(new SpotTracker());
  const [ready, setReady] = useState(false);
  const [pictureSize, setPictureSize] = useState<string | undefined>();
  const [torch, setTorch] = useState(true);
  const [redFilter, setRedFilter] = useState(true);
  const [detecting, setDetecting] = useState(true);
  const [spots, setSpots] = useState<Spot[]>([]);
  const [found, setFound] = useState(0);

  // Smallest picture size >= 480px wide keeps decoding fast
  const onReady = useCallback(async () => {
    setReady(true);
    try {
      const sizes = (await camera.current?.getAvailablePictureSizesAsync()) ?? [];
      const parsed = sizes
        .map((s) => ({ s, w: Number(s.split('x')[0]) }))
        .filter((p) => p.w >= 480)
        .sort((a, b) => a.w - b.w);
      if (parsed[0]) setPictureSize(parsed[0].s);
    } catch {
      // Keep the default size
    }
  }, []);

  useEffect(() => {
    if (!focused || !ready || !detecting) return;
    const spotTracker = tracker.current;
    let alive = true;
    (async () => {
      while (alive) {
        try {
          const pic = await camera.current?.takePictureAsync({
            quality: 0.4, base64: true, skipProcessing: true, shutterSound: false,
          });
          if (!alive || !pic?.base64) continue;
          const img = decode(base64ToBytes(pic.base64), { useTArray: true, formatAsRGBA: true });
          let hits = spotTracker.update(detectSpots(img.data, img.width, img.height));
          // Sensor frames are landscape; rotate into the portrait preview
          if (img.width > img.height) hits = hits.map((s) => ({ ...s, x: 1 - s.y, y: s.x }));
          setSpots(hits);
          if (hits.length) {
            setFound((n) => n + hits.length);
            Haptics.notificationAsync(Haptics.NotificationFeedbackType.Warning);
          }
        } catch {
          await new Promise((r) => setTimeout(r, 300));
        }
      }
    })();
    return () => {
      alive = false;
      spotTracker.reset();
      setSpots([]);
    };
  }, [focused, ready, detecting]);

  if (!permission) return <View style={{ flex: 1, backgroundColor: c.bg }} />;
  if (!permission.granted) {
    return (
      <Screen title="Lens" subtitle="Find cameras that are offline or powered off">
        <EmptyState
          icon="camera-iris"
          title="Camera access needed"
          body="Every camera lens reflects light straight back. With the flashlight on, the app spots those reflections, even on cameras that are switched off."
        />
        <Button label="Allow camera" icon="camera" onPress={requestPermission} />
      </Screen>
    );
  }

  return (
    <View style={{ flex: 1, backgroundColor: '#000' }}>
      {focused && (
        <CameraView
          ref={camera}
          style={StyleSheet.absoluteFill}
          facing="back"
          enableTorch={torch}
          animateShutter={false}
          pictureSize={pictureSize}
          onCameraReady={onReady}
        />
      )}
      {redFilter && <View pointerEvents="none" style={[StyleSheet.absoluteFill, { backgroundColor: 'rgba(255,0,0,0.28)' }]} />}

      <View pointerEvents="none" style={StyleSheet.absoluteFill}>
        {spots.map((s, i) => (
          <View
            key={i}
            style={[styles.marker, {
              left: `${s.x * 100}%`, top: `${s.y * 100}%`,
              borderColor: s.kind === 'ir' ? '#D86BFF' : riskColors.CRITICAL,
            }]}
          >
            <Text style={styles.markerLabel}>{s.kind === 'ir' ? 'IR' : 'LENS'}</Text>
          </View>
        ))}
      </View>

      <View style={[styles.top, { paddingTop: insets.top + space.sm }]}>
        <View style={[styles.banner, { backgroundColor: 'rgba(11,13,16,0.72)' }]}>
          <Text style={[type.heading, { color: '#fff' }]}>Lens finder</Text>
          <Text style={[type.small, { color: '#C9CED6', marginTop: 2 }]}>
            Darken the room. Sweep slowly. A fixed bright dot that stays on one object may be a lens.
          </Text>
          <Text style={[type.caption, { color: found ? riskColors.HIGH : '#8A93A3', marginTop: space.sm }]}>
            {detecting ? `AUTO-DETECT ON · ${found} CANDIDATE${found === 1 ? '' : 'S'}` : 'AUTO-DETECT OFF'}
          </Text>
        </View>
      </View>

      <View style={[styles.controls, { bottom: insets.bottom + 96 }]}>
        <Toggle icon={torch ? 'flashlight' : 'flashlight-off'} label="Light" on={torch} onPress={() => setTorch((t) => !t)} />
        <Toggle icon="filter" label="Red" on={redFilter} onPress={() => setRedFilter((r) => !r)} />
        <Toggle icon="target" label="Detect" on={detecting} onPress={() => setDetecting((d) => !d)} />
        <Toggle icon="restart" label="Reset" on={false} onPress={() => (setFound(0), tracker.current.reset(), setSpots([]))} />
      </View>
    </View>
  );
}

function Toggle({ icon, label, on, onPress }: { icon: Parameters<typeof Icon>[0]['name']; label: string; on: boolean; onPress: () => void }) {
  const c = usePalette();
  return (
    <Pressable onPress={onPress} style={({ pressed }) => [styles.toggle, { opacity: pressed ? 0.7 : 1 }]}>
      <View style={[styles.toggleIcon, { backgroundColor: on ? c.accent : 'rgba(11,13,16,0.72)' }]}>
        <Icon name={icon} size={22} color="#fff" />
      </View>
      <Text style={[type.caption, { color: '#fff', marginTop: 6 }]}>{label.toUpperCase()}</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  top: { position: 'absolute', left: space.lg, right: space.lg },
  banner: { borderRadius: radius.lg, padding: space.lg },
  controls: { position: 'absolute', left: 0, right: 0, flexDirection: 'row', justifyContent: 'space-evenly' },
  toggle: { alignItems: 'center' },
  toggleIcon: { width: 54, height: 54, borderRadius: 27, alignItems: 'center', justifyContent: 'center' },
  marker: {
    position: 'absolute', width: 44, height: 44, marginLeft: -22, marginTop: -22,
    borderRadius: 22, borderWidth: 2.5, alignItems: 'center', justifyContent: 'flex-end',
  },
  markerLabel: { position: 'absolute', bottom: -18, color: '#fff', fontSize: 10, fontWeight: '700', letterSpacing: 0.5 },
});
