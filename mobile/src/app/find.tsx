import * as Haptics from 'expo-haptics';
import { useEffect, useRef, useState } from 'react';
import { StyleSheet, Text, View } from 'react-native';

import { watchBleRssi } from '@/detect/ble';
import type { Finding } from '@/detect/types';
import { readAccessPointRssi } from '@/detect/wifi';
import { setState, useStore } from '@/state/store';
import { Button, Card, EmptyState, Screen, SectionTitle } from '@/ui/components';
import { FindingRow, isLocatable } from '@/ui/FindingViews';
import { Gauge } from '@/ui/Gauge';
import { riskColors, space, type, usePalette } from '@/ui/theme';

/** -95 dBm (far) .. -35 dBm (touching) -> 0..1 */
const toFraction = (dbm: number) => Math.max(0, Math.min(1, (dbm + 95) / 60));

function heat(dbm: number | null) {
  if (dbm == null) return { label: 'Searching…', color: '#8A93A3' };
  if (dbm >= -50) return { label: 'Very hot', color: riskColors.CRITICAL };
  if (dbm >= -62) return { label: 'Hot', color: riskColors.HIGH };
  if (dbm >= -75) return { label: 'Warm', color: riskColors.MODERATE };
  return { label: 'Cold', color: riskColors.INFO };
}

export default function FindScreen() {
  const c = usePalette();
  const target = useStore((s) => s.locateTarget);
  const findings = useStore((s) => s.findings);
  const candidates = findings.filter(isLocatable);

  if (target) return <Locator key={target.id} target={target} />;

  return (
    <Screen title="Find" subtitle="Walk toward a device using its signal">
      <SectionTitle>Locatable devices</SectionTitle>
      <Card style={{ paddingVertical: 0 }}>
        {candidates.length === 0 ? (
          <EmptyState icon="crosshairs-question" title="Nothing to track yet" body="Run a scan first. Nearby WiFi and Bluetooth findings can be tracked from here." />
        ) : (
          candidates.map((f, i) => (
            <FindingRow key={f.id} finding={f} last={i === candidates.length - 1} onPress={() => setState({ locateTarget: f })} />
          ))
        )}
      </Card>
      <Text style={[type.small, styles.note, { color: c.textMuted }]}>
        Devices on your own WiFi can’t be ranged from a phone. Run the laptop scanner with --locate mon:&lt;MAC&gt; for those.
      </Text>
    </Screen>
  );
}

function Locator({ target }: { target: Finding }) {
  const [rssi, setRssi] = useState<number | null>(null);
  const [peak, setPeak] = useState<number | null>(null);
  const [error, setError] = useState<string | null>(null);
  const smooth = useRef<number | null>(null);

  // Read signal for this target (component is keyed by target, so state starts fresh)
  useEffect(() => {
    let stop = () => {};
    let alive = true;
    const push = (dbm: number) => {
      // Exponential smoothing: raw RSSI jumps several dB between readings
      smooth.current = smooth.current == null ? dbm : smooth.current * 0.7 + dbm * 0.3;
      const v = Math.round(smooth.current);
      setRssi(v);
      setPeak((p) => (p == null || v > p ? v : p));
    };
    if (target.id.startsWith('demo:')) {
      // Demo data has no radio behind it: simulate a signal around the sample value
      const t = setInterval(() => push((target.rssi ?? -60) + Math.round(Math.random() * 6 - 3)), 600);
      stop = () => clearInterval(t);
    } else if (target.source === 'ble') {
      watchBleRssi(target.address, push).then((s) => (alive ? (stop = s) : s())).catch((e) => setError(String(e.message ?? e)));
    } else if (target.source === 'wifi') {
      const loop = async () => {
        while (alive) {
          try {
            const v = await readAccessPointRssi(target.address);
            if (v != null) push(v);
          } catch (e) {
            setError(e instanceof Error ? e.message : String(e));
          }
          await new Promise((r) => setTimeout(r, 2500));
        }
      };
      loop();
    }
    return () => {
      alive = false;
      stop();
    };
  }, [target]);

  // Geiger-style haptics: faster ticks when closer
  useEffect(() => {
    if (rssi == null) return;
    const interval = 150 + (1 - toFraction(rssi)) * 1200;
    const t = setInterval(() => Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light), interval);
    return () => clearInterval(t);
  }, [rssi]);

  const h = heat(rssi);

  return (
    <Screen title="Find" subtitle={target.title} right={<Button kind="secondary" label="Change" onPress={() => setState({ locateTarget: null })} />}>
      <View style={{ marginTop: space.md }}>
        <Gauge
          fraction={rssi == null ? 0 : toFraction(rssi)}
          color={h.color}
          value={rssi == null ? '—' : String(rssi)}
          unit="dBm"
          caption={h.label}
        />
      </View>

      <Card style={{ marginTop: space.lg }}>
        <Row label="Target" value={target.address} mono />
        <Row label="Strongest so far" value={peak == null ? '—' : `${peak} dBm`} />
        <Row label="Source" value={target.source === 'ble' ? 'Bluetooth (live)' : 'WiFi (updates every few seconds)'} last />
      </Card>

      {error && <Text style={[type.small, styles.note, { color: riskColors.HIGH }]}>{error}</Text>}

      <SectionTitle>How to use</SectionTitle>
      <Card>
        <Tip n={1} text="Hold the phone in front of you and turn slowly in a full circle. Note where the number is highest." />
        <Tip n={2} text="Walk in that direction. The vibration speeds up and the number rises as you get closer." />
        <Tip n={3} text="At the strongest spot, search within arm’s reach: smoke detectors, chargers, vents, clocks." />
        {target.source === 'wifi' && (
          <Tip n={4} text="Android limits WiFi scans. For faster updates, turn off “WiFi scan throttling” in Developer options." />
        )}
      </Card>
    </Screen>
  );
}

function Row({ label, value, mono, last }: { label: string; value: string; mono?: boolean; last?: boolean }) {
  const c = usePalette();
  return (
    <View style={[styles.row, !last && { borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: c.border }]}>
      <Text style={[type.small, { color: c.textMuted }]}>{label}</Text>
      <Text style={[mono ? type.mono : type.small, { color: c.text, flexShrink: 1, textAlign: 'right' }]}>{value}</Text>
    </View>
  );
}

function Tip({ n, text }: { n: number; text: string }) {
  const c = usePalette();
  return (
    <View style={[styles.tip, n > 1 && { marginTop: space.md }]}>
      <Text style={[type.heading, { color: c.accent, width: 18 }]}>{n}</Text>
      <Text style={[type.small, { color: c.text, flex: 1, lineHeight: 19 }]}>{text}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  note: { marginTop: space.md, marginHorizontal: space.xs, lineHeight: 19 },
  row: { flexDirection: 'row', justifyContent: 'space-between', gap: space.md, paddingVertical: space.sm },
  tip: { flexDirection: 'row', gap: space.sm },
});
