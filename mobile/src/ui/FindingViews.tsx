import * as Haptics from 'expo-haptics';
import { router } from 'expo-router';
import { Modal, Pressable, ScrollView, StyleSheet, Text, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import type { Finding, Source } from '@/detect/types';
import { setState, toggleTrusted } from '@/state/store';

import { Button, Icon, RiskPill, Tag, type IconName } from './components';
import { radius, riskColors, space, type, usePalette } from './theme';

export const sourceMeta: Record<Source, { icon: IconName; label: string }> = {
  lan: { icon: 'lan', label: 'Your network' },
  wifi: { icon: 'wifi', label: 'Nearby WiFi' },
  ble: { icon: 'bluetooth', label: 'Bluetooth' },
  laptop: { icon: 'laptop', label: 'Laptop scan' },
};

/** Sources whose signal strength a phone can track for the locator. */
export const isLocatable = (f: Finding) => f.source === 'wifi' || f.source === 'ble';

export function FindingRow({ finding, onPress, last }: { finding: Finding; onPress: () => void; last?: boolean }) {
  const c = usePalette();
  const meta = sourceMeta[finding.source];
  const color = finding.trusted ? c.textFaint : riskColors[finding.risk];
  return (
    <Pressable
      onPress={onPress}
      style={({ pressed }) => [
        styles.row,
        !last && { borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: c.border },
        pressed && { opacity: 0.6 },
      ]}
    >
      <View style={[styles.rowIcon, { backgroundColor: color + '1F' }]}>
        <Icon name={meta.icon} size={18} color={color} />
      </View>
      <View style={{ flex: 1 }}>
        <View style={styles.rowTitle}>
          <Text numberOfLines={1} style={[type.body, { color: c.text, fontWeight: '600', flexShrink: 1 }]}>
            {finding.title}
          </Text>
          {finding.isNew && <Tag label="NEW" color={riskColors.CRITICAL} />}
        </View>
        <Text numberOfLines={1} style={[type.small, { color: c.textMuted, marginTop: 2 }]}>
          {finding.trusted ? 'Trusted · ' : ''}{finding.manufacturer !== 'Unknown' ? `${finding.manufacturer} · ` : ''}{finding.address}
        </Text>
      </View>
      <RiskPill risk={finding.risk} compact />
      <Icon name="chevron-right" size={20} color={c.textFaint} />
    </Pressable>
  );
}

export function FindingSheet({ finding, onClose }: { finding: Finding | null; onClose: () => void }) {
  const c = usePalette();
  const insets = useSafeAreaInsets();
  if (!finding) return null;
  const meta = sourceMeta[finding.source];

  const locate = () => {
    Haptics.selectionAsync();
    setState({ locateTarget: finding });
    onClose();
    router.navigate('/find');
  };

  return (
    <Modal visible transparent animationType="slide" onRequestClose={onClose}>
      <Pressable style={[styles.backdrop, { backgroundColor: c.overlay }]} onPress={onClose} />
      <View style={[styles.sheet, { backgroundColor: c.surface, paddingBottom: insets.bottom + space.lg }]}>
        <View style={[styles.grabber, { backgroundColor: c.border }]} />
        <ScrollView contentContainerStyle={{ padding: space.xl, paddingTop: space.md }}>
          <View style={{ flexDirection: 'row', gap: space.sm, marginBottom: space.md }}>
            <RiskPill risk={finding.risk} />
            <Tag label={meta.label.toUpperCase()} />
            {finding.isNew && <Tag label="NEW" color={riskColors.CRITICAL} />}
          </View>
          <Text style={[type.title, { color: c.text, fontSize: 24 }]}>{finding.title}</Text>
          <Text selectable style={[type.mono, { color: c.textMuted, marginTop: 4 }]}>{finding.address}</Text>

          <Detail label="Why it was flagged" body={finding.evidence} />
          <Detail label="What to do" body={finding.recommendation} color={riskColors[finding.risk]} />
          {finding.manufacturer !== 'Unknown' && <Detail label="Identified as" body={finding.manufacturer} />}
          {finding.ports?.length ? <Detail label="Open ports" body={finding.ports.join(', ')} mono /> : null}

          <View style={{ gap: space.sm, marginTop: space.xl }}>
            {isLocatable(finding) && <Button label="Find it" icon="crosshairs-gps" onPress={locate} />}
            <Button
              kind="secondary"
              icon={finding.trusted ? 'shield-off-outline' : 'shield-check-outline'}
              label={finding.trusted ? 'Remove from trusted' : 'This is my device'}
              onPress={() => {
                toggleTrusted(finding);
                onClose();
              }}
            />
          </View>
        </ScrollView>
      </View>
    </Modal>
  );
}

function Detail({ label, body, color, mono }: { label: string; body: string; color?: string; mono?: boolean }) {
  const c = usePalette();
  return (
    <View style={{ marginTop: space.lg }}>
      <Text style={[type.caption, { color: c.textFaint, marginBottom: 4 }]}>{label.toUpperCase()}</Text>
      <Text selectable style={[mono ? type.mono : type.body, { color: color ?? c.text, lineHeight: 21 }]}>{body}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  row: { flexDirection: 'row', alignItems: 'center', gap: space.md, paddingVertical: space.md },
  rowIcon: { width: 36, height: 36, borderRadius: radius.sm, alignItems: 'center', justifyContent: 'center' },
  rowTitle: { flexDirection: 'row', alignItems: 'center', gap: space.sm },
  backdrop: { position: 'absolute', top: 0, left: 0, right: 0, bottom: 0 },
  sheet: { position: 'absolute', left: 0, right: 0, bottom: 0, maxHeight: '85%', borderTopLeftRadius: 24, borderTopRightRadius: 24 },
  grabber: { width: 36, height: 5, borderRadius: 3, alignSelf: 'center', marginTop: space.sm },
});
