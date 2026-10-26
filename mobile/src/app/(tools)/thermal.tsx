import * as ImagePicker from 'expo-image-picker';
import { useState } from 'react';
import { Image, Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';

import { Button, Card, Icon, Screen, SectionTitle } from '@/ui/components';
import { radius, riskColors, space, type, usePalette } from '@/ui/theme';

interface HotSpot {
  id: string;
  x: number;
  y: number;
  label: string;
}

export default function ThermalScreen() {
  const c = usePalette();
  const [imageUri, setImageUri] = useState<string | null>(null);
  const [hotspots, setHotspots] = useState<HotSpot[]>([]);

  const pickImage = async () => {
    const result = await ImagePicker.launchImageLibraryAsync({
      mediaTypes: ['images'],
      quality: 1,
    });
    if (!result.canceled && result.assets[0]) {
      setImageUri(result.assets[0].uri);
      setHotspots([]);
    }
  };

  const takePhoto = async () => {
    const { status } = await ImagePicker.requestCameraPermissionsAsync();
    if (status !== 'granted') return;
    const result = await ImagePicker.launchCameraAsync({
      quality: 1,
    });
    if (!result.canceled && result.assets[0]) {
      setImageUri(result.assets[0].uri);
      setHotspots([]);
    }
  };

  const addHotspot = (evt: { nativeEvent: { locationX: number; locationY: number } }) => {
    const { locationX, locationY } = evt.nativeEvent;
    const id = `hs-${Date.now()}`;
    setHotspots((prev) => [
      ...prev,
      { id, x: locationX, y: locationY, label: `Spot ${prev.length + 1}` },
    ]);
  };

  const removeHotspot = (id: string) => {
    setHotspots((prev) => prev.filter((h) => h.id !== id));
  };

  return (
    <Screen title="Thermal">
      <SectionTitle>Thermal anomaly detection</SectionTitle>
      <Card>
        <Text style={[type.small, { color: c.textMuted, lineHeight: 19 }]}>
          Powered electronics generate heat. A hidden camera behind a wall, inside a
          smoke detector, or in a power adapter will show as a warm spot on a thermal
          image. Use a FLIR One, Seek Thermal, or similar phone attachment.
        </Text>
      </Card>

      <SectionTitle>How to use</SectionTitle>
      <Card>
        {[
          'Attach a thermal camera to your phone (FLIR One, Seek Thermal, etc.)',
          'Take a thermal photo of walls, ceilings, smoke detectors, outlets, and vents',
          'Import the thermal image below',
          'Tap hot spots on the image to mark them for investigation',
          'A warm spot with no obvious cause (not near a pipe or outlet) is suspicious',
        ].map((step, i) => (
          <View key={i} style={styles.step}>
            <View style={[styles.stepNum, { backgroundColor: c.accent }]}>
              <Text style={[type.small, { color: '#fff', fontWeight: '700' }]}>{i + 1}</Text>
            </View>
            <Text style={[type.small, { color: c.text, flex: 1, lineHeight: 19 }]}>{step}</Text>
          </View>
        ))}
      </Card>

      <SectionTitle>Thermal image</SectionTitle>
      <Card>
        {imageUri ? (
          <View>
            <Pressable onPress={addHotspot}>
              <Image source={{ uri: imageUri }} style={styles.thermalImage} resizeMode="contain" />
              {hotspots.map((hs) => (
                <Pressable
                  key={hs.id}
                  onPress={() => removeHotspot(hs.id)}
                  style={[styles.hotspotMarker, { left: hs.x - 16, top: hs.y - 16 }]}
                >
                  <Icon name="alert-circle" size={32} color={riskColors.CRITICAL} />
                </Pressable>
              ))}
            </Pressable>
            {hotspots.length > 0 && (
              <Text style={[type.small, { color: riskColors.HIGH, marginTop: space.md }]}>
                {hotspots.length} hot spot{hotspots.length > 1 ? 's' : ''} marked — investigate these locations
              </Text>
            )}
            <View style={{ flexDirection: 'row', gap: space.sm, marginTop: space.md }}>
              <View style={{ flex: 1 }}>
                <Button kind="secondary" icon="refresh" label="New image" onPress={() => { setImageUri(null); setHotspots([]); }} />
              </View>
              <View style={{ flex: 1 }}>
                <Button kind="secondary" icon="delete-outline" label="Clear spots" onPress={() => setHotspots([])} />
              </View>
            </View>
          </View>
        ) : (
          <View style={{ gap: space.sm }}>
            <Button icon="camera" label="Take thermal photo" onPress={takePhoto} />
            <Button kind="secondary" icon="image" label="Import from gallery" onPress={pickImage} />
          </View>
        )}
      </Card>

      <SectionTitle>What to look for</SectionTitle>
      <Card>
        {[
          { label: 'Warm spot on a wall or ceiling', detail: 'Could be a camera or transmitter behind the surface', risk: 'HIGH' },
          { label: 'Hot smoke detector', detail: 'Some spy cameras are disguised as smoke detectors — they run warm', risk: 'HIGH' },
          { label: 'Warm power adapter or USB charger', detail: 'Hidden cameras are often built into chargers and adapters', risk: 'MODERATE' },
          { label: 'Unexplained heat near a vent or outlet', detail: 'Cameras are sometimes hidden inside air vents or electrical boxes', risk: 'MODERATE' },
          { label: 'Warm picture frame or clock', detail: 'Pinhole cameras can be embedded in everyday objects', risk: 'MODERATE' },
        ].map((item) => (
          <View key={item.label} style={[styles.hint, { borderBottomColor: c.border }]}>
            <View style={[styles.riskDot, { backgroundColor: riskColors[item.risk as keyof typeof riskColors] }]} />
            <View style={{ flex: 1 }}>
              <Text style={[type.body, { color: c.text, fontWeight: '600' }]}>{item.label}</Text>
              <Text style={[type.small, { color: c.textMuted, lineHeight: 18 }]}>{item.detail}</Text>
            </View>
          </View>
        ))}
      </Card>

      <SectionTitle>No thermal camera?</SectionTitle>
      <Card>
        <Text style={[type.small, { color: c.textMuted, lineHeight: 19 }]}>
          You can still check for heat manually: run your hand slowly along walls, ceilings,
          and objects. Electronics generate noticeable warmth — especially in a room that has
          been closed for a while. Focus on smoke detectors, picture frames, clocks, USB
          chargers, and any object that feels warmer than its surroundings.
        </Text>
      </Card>
    </Screen>
  );
}

const styles = StyleSheet.create({
  step: { flexDirection: 'row', alignItems: 'flex-start', gap: space.sm, marginTop: space.sm },
  stepNum: {
    width: 22, height: 22, borderRadius: 11,
    alignItems: 'center', justifyContent: 'center', marginTop: 1,
  },
  thermalImage: { width: '100%', height: 300, borderRadius: radius.md },
  hotspotMarker: { position: 'absolute' },
  hint: {
    flexDirection: 'row', alignItems: 'flex-start', gap: space.sm,
    paddingVertical: space.sm, borderBottomWidth: StyleSheet.hairlineWidth,
  },
  riskDot: { width: 10, height: 10, borderRadius: 5, marginTop: 5 },
});
