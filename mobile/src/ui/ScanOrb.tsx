import { useEffect, useState } from 'react';
import { Animated, Easing, Pressable, StyleSheet, Text, View } from 'react-native';
import Svg, { Circle } from 'react-native-svg';

import { type, usePalette } from './theme';

const SIZE = 200;
const STROKE = 6;
const R = (SIZE - STROKE) / 2;
const CIRC = 2 * Math.PI * R;

/** Big circular scan button: radar pulse while scanning, progress ring around it. */
export function ScanOrb({ scanning, progress, color, label, sublabel, onPress }: {
  scanning: boolean;
  progress: number;
  color: string;
  label: string;
  sublabel?: string;
  onPress: () => void;
}) {
  const c = usePalette();
  const [pulse] = useState(() => new Animated.Value(0));

  useEffect(() => {
    if (!scanning) {
      pulse.stopAnimation();
      pulse.setValue(0);
      return;
    }
    const loop = Animated.loop(
      Animated.timing(pulse, { toValue: 1, duration: 1800, easing: Easing.out(Easing.quad), useNativeDriver: true }),
    );
    loop.start();
    return () => loop.stop();
  }, [scanning, pulse]);

  const ring = (delay: number) => {
    const t = Animated.modulo(Animated.add(pulse, delay), 1);
    return {
      opacity: t.interpolate({ inputRange: [0, 1], outputRange: [0.35, 0] }),
      transform: [{ scale: t.interpolate({ inputRange: [0, 1], outputRange: [1, 1.5] }) }],
    };
  };

  return (
    <View style={styles.wrap}>
      {scanning && (
        <>
          <Animated.View style={[styles.ring, { borderColor: color }, ring(0)]} />
          <Animated.View style={[styles.ring, { borderColor: color }, ring(0.5)]} />
        </>
      )}
      <Pressable
        onPress={onPress}
        disabled={scanning}
        accessibilityRole="button"
        accessibilityLabel={label}
        style={({ pressed }) => [styles.orb, { backgroundColor: c.surface, transform: [{ scale: pressed ? 0.97 : 1 }] }]}
      >
        <Svg width={SIZE} height={SIZE} style={StyleSheet.absoluteFill}>
          <Circle cx={SIZE / 2} cy={SIZE / 2} r={R} stroke={c.border} strokeWidth={STROKE} fill="none" />
          {progress > 0 && <Circle
            cx={SIZE / 2}
            cy={SIZE / 2}
            r={R}
            stroke={color}
            strokeWidth={STROKE}
            fill="none"
            strokeLinecap="round"
            strokeDasharray={`${CIRC} ${CIRC}`}
            strokeDashoffset={CIRC * (1 - progress)}
            rotation={-90}
            originX={SIZE / 2}
            originY={SIZE / 2}
          />}
        </Svg>
        <Text style={[type.title, { color: c.text, fontSize: 30 }]}>{label}</Text>
        {sublabel ? <Text style={[type.small, { color: c.textMuted, marginTop: 4 }]}>{sublabel}</Text> : null}
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  wrap: { width: SIZE * 1.5, height: SIZE * 1.3, alignItems: 'center', justifyContent: 'center', alignSelf: 'center' },
  ring: { position: 'absolute', width: SIZE, height: SIZE, borderRadius: SIZE / 2, borderWidth: 2 },
  orb: { width: SIZE, height: SIZE, borderRadius: SIZE / 2, alignItems: 'center', justifyContent: 'center' },
});
