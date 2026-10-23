import * as Haptics from 'expo-haptics';
import { useCallback, useEffect, useRef, useState } from 'react';
import { Dimensions, StyleSheet, Text, View } from 'react-native';

import { scanAccessPoints } from '@/detect/wifi';
import { Button, Card, EmptyState, Screen, SectionTitle } from '@/ui/components';
import { riskColors, space, type, usePalette } from '@/ui/theme';

interface HeatPoint {
  x: number;
  y: number;
  rssi: number;
  bssid: string;
  ssid: string;
}

const GRID = 10;
const windowW = Dimensions.get('window').width - space.lg * 2;
const cellSize = Math.floor(windowW / GRID);
const mapSize = cellSize * GRID;

function rssiColor(dbm: number): string {
  if (dbm >= -50) return '#FF3B30';
  if (dbm >= -60) return '#FF9500';
  if (dbm >= -70) return '#FFCC00';
  if (dbm >= -80) return '#34C759';
  return '#007AFF';
}

function rssiOpacity(dbm: number): number {
  return Math.max(0.15, Math.min(1, (dbm + 95) / 50));
}

export default function HeatmapScreen() {
  const c = usePalette();
  const [tracking, setTracking] = useState(false);
  const [points, setPoints] = useState<HeatPoint[]>([]);
  const [cursor, setCursor] = useState({ x: 0, y: 0 });
  const [target, setTarget] = useState<{ bssid: string; ssid: string } | null>(null);
  const [allAPs, setAllAPs] = useState<{ bssid: string; ssid: string; level: number }[]>([]);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const grid = useRef<(number | null)[][]>(
    Array.from({ length: GRID }, () => Array(GRID).fill(null)),
  );

  const startTracking = useCallback(async () => {
    const aps = await scanAccessPoints();
    setAllAPs(aps.map((a) => ({ bssid: a.bssid, ssid: a.ssid, level: a.level })));
    if (aps.length === 0) return;

    // Auto-select the strongest suspicious AP, or the strongest overall
    const sorted = [...aps].sort((a, b) => b.level - a.level);
    setTarget({ bssid: sorted[0].bssid, ssid: sorted[0].ssid || 'Hidden' });
    setTracking(true);
  }, []);

  useEffect(() => {
    if (!tracking || !target) return;
    const poll = async () => {
      try {
        const aps = await scanAccessPoints();
        const ap = aps.find((a) => a.bssid.toUpperCase() === target.bssid.toUpperCase());
        if (ap) {
          Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Light);
          const pt: HeatPoint = { x: cursor.x, y: cursor.y, rssi: ap.level, bssid: ap.bssid, ssid: ap.ssid };
          setPoints((prev) => [...prev, pt]);
          grid.current[cursor.y][cursor.x] = ap.level;
        }
      } catch { /* scan throttled */ }
    };
    poll();
    intervalRef.current = setInterval(poll, 4000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [tracking, target, cursor.x, cursor.y]);

  const stop = () => {
    setTracking(false);
    if (intervalRef.current) clearInterval(intervalRef.current);
  };

  const reset = () => {
    stop();
    setPoints([]);
    setTarget(null);
    grid.current = Array.from({ length: GRID }, () => Array(GRID).fill(null));
  };

  if (!tracking && points.length === 0) {
    return (
      <Screen title="Heatmap" subtitle="Map signal strength around the room">
        <SectionTitle>How it works</SectionTitle>
        <Card>
          <Tip n={1} text="Tap Start, then stand in one corner of the room." />
          <Tip n={2} text="Tap a cell on the grid. Walk there, wait for the reading." />
          <Tip n={3} text="Repeat for each position. Red = strongest signal = device is close." />
          <Tip n={4} text="The heatmap shows where the hidden camera most likely is." />
        </Card>
        <View style={{ marginTop: space.lg }}>
          <Button icon="access-point" label="Start heatmap" onPress={startTracking} />
        </View>
      </Screen>
    );
  }

  const strongest = points.length
    ? points.reduce((a, b) => (a.rssi > b.rssi ? a : b))
    : null;

  return (
    <Screen title="Heatmap" subtitle={target ? `Tracking: ${target.ssid}` : 'Tap a cell and walk there'}>
      {/* Target selector */}
      {allAPs.length > 1 && (
        <View style={styles.apRow}>
          {allAPs.slice(0, 5).map((ap) => (
            <View key={ap.bssid} style={[
              styles.apChip,
              { backgroundColor: target?.bssid === ap.bssid ? c.accent : c.surface, borderColor: c.border },
            ]}>
              <Text
                style={[type.caption, { color: target?.bssid === ap.bssid ? '#fff' : c.text }]}
                onPress={() => { setTarget({ bssid: ap.bssid, ssid: ap.ssid || 'Hidden' }); setPoints([]); grid.current = Array.from({ length: GRID }, () => Array(GRID).fill(null)); }}
              >
                {(ap.ssid || ap.bssid.slice(-5)).slice(0, 12)} {ap.level}dBm
              </Text>
            </View>
          ))}
        </View>
      )}

      {/* Grid */}
      <View style={[styles.grid, { width: mapSize, height: mapSize, borderColor: c.border }]}>
        {Array.from({ length: GRID }, (_, row) => (
          <View key={row} style={{ flexDirection: 'row' }}>
            {Array.from({ length: GRID }, (_, col) => {
              const val = grid.current[row][col];
              const isActive = cursor.x === col && cursor.y === row && tracking;
              return (
                <View
                  key={col}
                  onStartShouldSetResponder={() => true}
                  onResponderRelease={() => setCursor({ x: col, y: row })}
                  style={[
                    styles.cell,
                    {
                      width: cellSize,
                      height: cellSize,
                      borderColor: c.border,
                      backgroundColor: val != null ? rssiColor(val) : c.surfaceAlt,
                      opacity: val != null ? rssiOpacity(val) : isActive ? 0.5 : 0.15,
                    },
                    isActive && { borderColor: c.accent, borderWidth: 2 },
                  ]}
                >
                  {val != null && (
                    <Text style={[type.caption, { color: '#fff', fontSize: 9 }]}>{val}</Text>
                  )}
                </View>
              );
            })}
          </View>
        ))}
      </View>

      {/* Legend */}
      <View style={styles.legend}>
        {[[-50, 'Very hot'], [-60, 'Hot'], [-70, 'Warm'], [-80, 'Cool'], [-90, 'Cold']].map(
          ([dbm, label]) => (
            <View key={String(dbm)} style={styles.legendItem}>
              <View style={[styles.legendDot, { backgroundColor: rssiColor(dbm as number) }]} />
              <Text style={[type.caption, { color: c.textMuted }]}>{label as string}</Text>
            </View>
          ),
        )}
      </View>

      {/* Strongest point */}
      {strongest && (
        <Card style={{ marginTop: space.md }}>
          <Text style={[type.body, { color: c.text, fontWeight: '600' }]}>
            Strongest signal: {strongest.rssi} dBm at position ({strongest.x + 1}, {strongest.y + 1})
          </Text>
          <Text style={[type.small, { color: c.textMuted, marginTop: space.xs }]}>
            Walk to the red cells and search there: smoke detectors, chargers, vents, clocks.
          </Text>
        </Card>
      )}

      <View style={[styles.buttons, { marginTop: space.md }]}>
        <View style={{ flex: 1 }}><Button kind="secondary" icon="stop" label="Stop" onPress={stop} /></View>
        <View style={{ flex: 1 }}><Button kind="secondary" icon="refresh" label="Reset" onPress={reset} /></View>
      </View>
    </Screen>
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
  grid: { alignSelf: 'center', marginTop: space.md, borderWidth: 1, borderRadius: 8, overflow: 'hidden' },
  cell: { alignItems: 'center', justifyContent: 'center', borderWidth: StyleSheet.hairlineWidth },
  legend: { flexDirection: 'row', justifyContent: 'center', gap: space.md, marginTop: space.sm },
  legendItem: { flexDirection: 'row', alignItems: 'center', gap: 4 },
  legendDot: { width: 10, height: 10, borderRadius: 5 },
  apRow: { flexDirection: 'row', flexWrap: 'wrap', gap: space.xs, marginBottom: space.sm },
  apChip: { paddingHorizontal: space.sm, paddingVertical: 4, borderRadius: 12, borderWidth: StyleSheet.hairlineWidth },
  buttons: { flexDirection: 'row', gap: space.sm },
  tip: { flexDirection: 'row', gap: space.sm },
});
