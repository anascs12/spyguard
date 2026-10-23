import * as Haptics from 'expo-haptics';
import { useIsFocused } from 'expo-router';
import { Magnetometer } from 'expo-sensors';
import { useEffect, useRef, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';
import Svg, { Polyline } from 'react-native-svg';

import { Button, Card, EmptyState, Screen, SectionTitle } from '@/ui/components';
import { Gauge } from '@/ui/Gauge';
import { riskColors, space, type, usePalette } from '@/ui/theme';

const HISTORY = 90;
const CHART_W = 320;
const CHART_H = 64;

function level(delta: number) {
  if (delta >= 60) return { label: 'Strong source', color: riskColors.CRITICAL };
  if (delta >= 25) return { label: 'Something here', color: riskColors.HIGH };
  if (delta >= 10) return { label: 'Slight change', color: riskColors.MODERATE };
  return { label: 'Normal', color: riskColors.LOW };
}

export default function MagnetScreen() {
  const c = usePalette();
  const focused = useIsFocused();
  const [available, setAvailable] = useState<boolean | null>(null);
  const [field, setField] = useState(0);
  const [baseline, setBaseline] = useState<number | null>(null);
  const [history, setHistory] = useState<number[]>([]);
  const samples = useRef<number[]>([]);
  const calibration = useRef<number[]>([]);
  const lastBuzz = useRef(0);

  useEffect(() => {
    Magnetometer.isAvailableAsync().then(setAvailable);
  }, []);

  useEffect(() => {
    if (!focused || !available) return;
    Magnetometer.setUpdateInterval(100);
    const sub = Magnetometer.addListener(({ x, y, z }) => {
      const m = Math.sqrt(x * x + y * y + z * z);
      samples.current.push(m);
      if (samples.current.length > 5) samples.current.shift();
      const avg = samples.current.reduce((a, b) => a + b, 0) / samples.current.length;
      setField(avg);
      setHistory((h) => [...h.slice(-(HISTORY - 1)), avg]);
      // Calibrate on the open room: Earth's field is ~25-65 µT depending on location
      if (calibration.current.length < 20) {
        calibration.current.push(avg);
        if (calibration.current.length === 20) {
          const sorted = [...calibration.current].sort((a, b) => a - b);
          setBaseline(sorted[10]);
        }
      }
    });
    return () => sub.remove();
  }, [focused, available]);

  const delta = baseline == null ? 0 : Math.abs(field - baseline);
  const lv = level(delta);

  useEffect(() => {
    const now = Date.now();
    if (delta >= 25 && now - lastBuzz.current > 400) {
      lastBuzz.current = now;
      Haptics.impactAsync(delta >= 60 ? Haptics.ImpactFeedbackStyle.Heavy : Haptics.ImpactFeedbackStyle.Light);
    }
  }, [delta]);

  if (available === false) {
    return (
      <Screen title="Magnet">
        <EmptyState icon="magnet" title="No magnetometer" body="This phone doesn’t have a magnetic sensor." />
      </Screen>
    );
  }

  const max = Math.max(...history, (baseline ?? 50) + 30);
  const min = Math.min(...history, (baseline ?? 50) - 10);
  const points = history
    .map((v, i) => `${(i / (HISTORY - 1)) * CHART_W},${CHART_H - ((v - min) / (max - min || 1)) * CHART_H}`)
    .join(' ');

  return (
    <Screen title="Magnet" subtitle="Detects electronics up close, even when switched off">
      <Gauge
        fraction={Math.min(1, delta / 80)}
        color={lv.color}
        value={baseline == null ? '…' : `+${Math.round(delta)}`}
        unit={baseline == null ? 'Calibrating, hold still' : 'µT above room level'}
        caption={baseline == null ? undefined : lv.label}
      />

      <Card style={{ marginTop: space.lg }}>
        <Svg width="100%" height={CHART_H} viewBox={`0 0 ${CHART_W} ${CHART_H}`} preserveAspectRatio="none">
          <Polyline points={points} fill="none" stroke={lv.color} strokeWidth={2} />
        </Svg>
        <View style={styles.legend}>
          <Text style={[type.small, { color: c.textMuted }]}>Field {Math.round(field)} µT</Text>
          <Text style={[type.small, { color: c.textMuted }]}>Room {baseline == null ? '—' : Math.round(baseline)} µT</Text>
        </View>
      </Card>

      <View style={{ marginTop: space.md }}>
        <Button kind="secondary" icon="target" label="Recalibrate here" onPress={() => {
          calibration.current = [];
          setBaseline(null);
          setHistory([]);
        }} />
      </View>

      <SectionTitle>How to sweep</SectionTitle>
      <Card>
        <Text style={[type.small, { color: c.text, lineHeight: 20 }]}>
          Calibrate in open space, away from metal. Then move the top of the phone slowly, a few centimetres from
          smoke detectors, clocks, chargers, frames and outlets. A jump that appears at the same spot every time
          points to electronics inside. Metal furniture, speakers and wiring also cause jumps, so check what you find.
        </Text>
      </Card>
    </Screen>
  );
}

const styles = StyleSheet.create({
  legend: { flexDirection: 'row', justifyContent: 'space-between', marginTop: space.sm },
});
