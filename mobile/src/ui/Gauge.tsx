import { StyleSheet, Text, View } from 'react-native';
import Svg, { Path } from 'react-native-svg';

import { type, usePalette } from './theme';

const W = 260;
const STROKE = 14;
const R = (W - STROKE) / 2;
const START = Math.PI * 0.75;
const SWEEP = Math.PI * 1.5;

function arc(fraction: number): string {
  const a0 = START;
  const a1 = START + SWEEP * Math.max(0.0001, Math.min(1, fraction));
  const cx = W / 2, cy = W / 2;
  const p = (a: number) => `${cx + R * Math.cos(a)} ${cy + R * Math.sin(a)}`;
  return `M ${p(a0)} A ${R} ${R} 0 ${a1 - a0 > Math.PI ? 1 : 0} 1 ${p(a1)}`;
}

/** 270° arc gauge with a big value in the middle. */
export function Gauge({ fraction, color, value, unit, caption }: {
  fraction: number;
  color: string;
  value: string;
  unit?: string;
  caption?: string;
}) {
  const c = usePalette();
  return (
    <View style={styles.wrap}>
      <Svg width={W} height={W}>
        <Path d={arc(1)} stroke={c.surfaceAlt} strokeWidth={STROKE} strokeLinecap="round" fill="none" />
        <Path d={arc(fraction)} stroke={color} strokeWidth={STROKE} strokeLinecap="round" fill="none" />
      </Svg>
      <View style={styles.center}>
        <Text style={[type.title, { color: c.text, fontSize: 52, letterSpacing: -1.5 }]}>{value}</Text>
        {unit ? <Text style={[type.small, { color: c.textMuted }]}>{unit}</Text> : null}
        {caption ? <Text style={[type.heading, { color, marginTop: 8 }]}>{caption}</Text> : null}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { width: W, height: W, alignSelf: 'center' },
  center: { position: 'absolute', top: 0, left: 0, right: 0, bottom: 0, alignItems: 'center', justifyContent: 'center' },
});
