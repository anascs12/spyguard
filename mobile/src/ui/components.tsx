import { MaterialCommunityIcons } from '@expo/vector-icons';
import type { ComponentProps, ReactNode } from 'react';
import { Pressable, ScrollView, StyleSheet, Text, View, type ViewStyle } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import type { Risk } from '@/detect/types';

import { radius, riskColors, riskLabels, space, type, usePalette } from './theme';

export type IconName = ComponentProps<typeof MaterialCommunityIcons>['name'];

export function Icon({ name, size = 20, color }: { name: IconName; size?: number; color?: string }) {
  const c = usePalette();
  return <MaterialCommunityIcons name={name} size={size} color={color ?? c.text} />;
}

export function Screen({ title, subtitle, children, scroll = true, right }: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  scroll?: boolean;
  right?: ReactNode;
}) {
  const c = usePalette();
  const insets = useSafeAreaInsets();
  const header = (
    <View style={styles.header}>
      <View style={{ flex: 1 }}>
        <Text style={[type.title, { color: c.text }]}>{title}</Text>
        {subtitle ? <Text style={[type.small, { color: c.textMuted, marginTop: 2 }]}>{subtitle}</Text> : null}
      </View>
      {right}
    </View>
  );
  const pad = { paddingTop: insets.top + space.md, paddingHorizontal: space.lg };
  if (!scroll) {
    return <View style={[{ flex: 1, backgroundColor: c.bg }, pad]}>{header}{children}</View>;
  }
  return (
    <View style={{ flex: 1, backgroundColor: c.bg }}>
      <ScrollView contentContainerStyle={[pad, { paddingBottom: insets.bottom + 120 }]}>
        {header}
        {children}
      </ScrollView>
      {/* Opaque strip so scrolled content never runs under the status bar */}
      <View pointerEvents="none" style={[styles.statusBar, { height: insets.top, backgroundColor: c.bg }]} />
    </View>
  );
}

export function Card({ children, style, onPress }: { children: ReactNode; style?: ViewStyle; onPress?: () => void }) {
  const c = usePalette();
  const base = [styles.card, { backgroundColor: c.surface, borderColor: c.border }, style];
  if (!onPress) return <View style={base}>{children}</View>;
  return (
    <Pressable onPress={onPress} style={({ pressed }) => [...base, pressed && { opacity: 0.7 }]}>
      {children}
    </Pressable>
  );
}

export function SectionTitle({ children }: { children: ReactNode }) {
  const c = usePalette();
  return <Text style={[type.caption, styles.section, { color: c.textFaint }]}>{String(children).toUpperCase()}</Text>;
}

export function Button({ label, icon, onPress, kind = 'primary', disabled }: {
  label: string;
  icon?: IconName;
  onPress: () => void;
  kind?: 'primary' | 'secondary' | 'danger';
  disabled?: boolean;
}) {
  const c = usePalette();
  const bg = kind === 'primary' ? c.accent : kind === 'danger' ? riskColors.CRITICAL : c.surfaceAlt;
  const fg = kind === 'secondary' ? c.text : c.accentText;
  return (
    <Pressable
      onPress={onPress}
      disabled={disabled}
      style={({ pressed }) => [styles.button, { backgroundColor: bg, opacity: disabled ? 0.4 : pressed ? 0.8 : 1 }]}
    >
      {icon ? <Icon name={icon} size={18} color={fg} /> : null}
      <Text style={[type.heading, { color: fg, fontSize: 15 }]}>{label}</Text>
    </Pressable>
  );
}

export function RiskPill({ risk, compact }: { risk: Risk; compact?: boolean }) {
  const color = riskColors[risk];
  return (
    <View style={[styles.pill, { backgroundColor: color + '22' }]}>
      <View style={[styles.dot, { backgroundColor: color }]} />
      {!compact && <Text style={[type.caption, { color }]}>{riskLabels[risk].toUpperCase()}</Text>}
    </View>
  );
}

export function Tag({ label, color }: { label: string; color?: string }) {
  const c = usePalette();
  return (
    <View style={[styles.pill, { backgroundColor: (color ?? c.textMuted) + '22' }]}>
      <Text style={[type.caption, { color: color ?? c.textMuted }]}>{label}</Text>
    </View>
  );
}

export function EmptyState({ icon, title, body }: { icon: IconName; title: string; body: string }) {
  const c = usePalette();
  return (
    <View style={styles.empty}>
      <View style={[styles.emptyIcon, { backgroundColor: c.surfaceAlt }]}>
        <Icon name={icon} size={26} color={c.textMuted} />
      </View>
      <Text style={[type.heading, { color: c.text, textAlign: 'center' }]}>{title}</Text>
      <Text style={[type.small, { color: c.textMuted, textAlign: 'center', marginTop: 4 }]}>{body}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  header: { flexDirection: 'row', alignItems: 'flex-start', marginBottom: space.lg },
  statusBar: { position: 'absolute', top: 0, left: 0, right: 0 },
  card: { borderRadius: radius.lg, borderWidth: StyleSheet.hairlineWidth, padding: space.lg },
  section: { marginTop: space.xl, marginBottom: space.sm, marginLeft: space.xs },
  button: {
    flexDirection: 'row', alignItems: 'center', justifyContent: 'center', gap: space.sm,
    height: 50, borderRadius: radius.md, paddingHorizontal: space.lg,
  },
  pill: {
    flexDirection: 'row', alignItems: 'center', gap: 6, alignSelf: 'flex-start',
    paddingHorizontal: 8, paddingVertical: 3, borderRadius: radius.pill,
  },
  dot: { width: 7, height: 7, borderRadius: 4 },
  empty: { alignItems: 'center', paddingVertical: space.xxl, paddingHorizontal: space.xl },
  emptyIcon: { width: 56, height: 56, borderRadius: 28, alignItems: 'center', justifyContent: 'center', marginBottom: space.md },
});
