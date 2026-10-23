import * as Haptics from 'expo-haptics';
import { useEffect, useMemo, useRef, useState } from 'react';
import { ActivityIndicator, StyleSheet, Text, View } from 'react-native';

import { runScan } from '@/detect/scan';
import { PHYSICAL_CHECKLIST } from '@/detect/signatures';
import { RISK_ORDER, type Finding, type Phase, type Risk } from '@/detect/types';
import { useStore } from '@/state/store';
import { Card, EmptyState, Icon, Screen, SectionTitle } from '@/ui/components';
import { FindingRow, FindingSheet } from '@/ui/FindingViews';
import { ScanOrb } from '@/ui/ScanOrb';
import { riskColors, riskLabels, space, type, usePalette } from '@/ui/theme';

function verdict(counts: Record<Risk, number>, scanned: boolean) {
  if (!scanned) return { label: 'Scan', sub: 'Tap to check this room', risk: null as Risk | null };
  if (counts.CRITICAL) return { label: `${counts.CRITICAL} found`, sub: 'Likely cameras nearby', risk: 'CRITICAL' as Risk };
  if (counts.HIGH) return { label: `${counts.HIGH} to check`, sub: 'Suspicious devices', risk: 'HIGH' as Risk };
  if (counts.MODERATE) return { label: 'Mostly clear', sub: `${counts.MODERATE} worth a look`, risk: 'MODERATE' as Risk };
  return { label: 'All clear', sub: 'Tap to scan again', risk: 'LOW' as Risk };
}

export default function ScanScreen() {
  const c = usePalette();
  const { scanning, progress, phases, findings, lastScan, demo } = useStore((s) => s);
  const [selected, setSelected] = useState<Finding | null>(null);
  const wasScanning = useRef(false);

  const active = findings.filter((f) => !f.trusted);
  const counts = useMemo(() => {
    const n = Object.fromEntries(RISK_ORDER.map((r) => [r, 0])) as Record<Risk, number>;
    active.forEach((f) => n[f.risk]++);
    return n;
  }, [active]);
  const v = verdict(counts, lastScan != null);

  useEffect(() => {
    if (wasScanning.current && !scanning) {
      Haptics.notificationAsync(
        counts.CRITICAL || counts.HIGH ? Haptics.NotificationFeedbackType.Warning : Haptics.NotificationFeedbackType.Success,
      );
    }
    wasScanning.current = scanning;
  }, [scanning, counts.CRITICAL, counts.HIGH]);

  const flagged = findings.filter((f) => f.trusted || f.risk !== 'INFO');
  const lastText = demo ? 'Demo data · sample results, not a real scan' : lastScan ? `Last scan ${new Date(lastScan).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}` : 'WiFi · nearby networks · Bluetooth';

  return (
    <Screen title="Privacy Scanner" subtitle={lastText}>
      <ScanOrb
        scanning={scanning}
        progress={scanning ? progress : lastScan ? 1 : 0}
        color={scanning ? c.accent : v.risk ? riskColors[v.risk] : c.accent}
        label={scanning ? `${Math.round(progress * 100)}%` : v.label}
        sublabel={scanning ? 'Scanning…' : v.sub}
        onPress={() => {
          Haptics.impactAsync(Haptics.ImpactFeedbackStyle.Medium);
          runScan();
        }}
      />

      {lastScan != null && !scanning && (
        <View style={styles.summary}>
          {(['CRITICAL', 'HIGH', 'MODERATE', 'LOW'] as Risk[]).map((r) => (
            <View key={r} style={[styles.stat, { backgroundColor: c.surface, borderColor: c.border }]}>
              <Text style={[type.title, { color: counts[r] ? riskColors[r] : c.textFaint, fontSize: 24 }]}>{counts[r]}</Text>
              <Text style={[type.caption, { color: c.textMuted }]}>{riskLabels[r].toUpperCase()}</Text>
            </View>
          ))}
        </View>
      )}

      {phases.length > 0 && (
        <>
          <SectionTitle>Checks</SectionTitle>
          <Card style={{ paddingVertical: space.sm }}>
            {phases.map((p, i) => <PhaseRow key={p.key} phase={p} last={i === phases.length - 1} />)}
          </Card>
        </>
      )}

      {lastScan != null && (
        <>
          <SectionTitle>Findings</SectionTitle>
          <Card style={{ paddingVertical: 0 }}>
            {flagged.length === 0 ? (
              <EmptyState icon="shield-check-outline" title="Nothing suspicious" body="Do the physical check below too: offline cameras don’t show up in radio scans." />
            ) : (
              flagged.map((f, i) => (
                <FindingRow key={f.id} finding={f} onPress={() => setSelected(f)} last={i === flagged.length - 1} />
              ))
            )}
          </Card>
        </>
      )}

      <SectionTitle>Physical check</SectionTitle>
      <Card>
        {PHYSICAL_CHECKLIST.map((step, i) => (
          <View key={i} style={[styles.step, i > 0 && { marginTop: space.md }]}>
            <View style={[styles.stepNum, { backgroundColor: c.surfaceAlt }]}>
              <Text style={[type.caption, { color: c.textMuted }]}>{i + 1}</Text>
            </View>
            <Text style={[type.small, { color: c.text, flex: 1, lineHeight: 19 }]}>
              {step.replace('Use --survey to measure from 3+ spots', 'Use Find to walk toward it')}
            </Text>
          </View>
        ))}
      </Card>

      <FindingSheet finding={selected} onClose={() => setSelected(null)} />
    </Screen>
  );
}

function PhaseRow({ phase, last }: { phase: Phase; last: boolean }) {
  const c = usePalette();
  const icon = {
    idle: <Icon name="circle-outline" size={18} color={c.textFaint} />,
    running: <ActivityIndicator size="small" color={c.accent} />,
    done: <Icon name="check-circle" size={18} color={riskColors.LOW} />,
    skipped: <Icon name="minus-circle-outline" size={18} color={c.textFaint} />,
    error: <Icon name="alert-circle-outline" size={18} color={riskColors.HIGH} />,
  }[phase.status];
  return (
    <View style={[styles.phase, !last && { borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: c.border }]}>
      <View style={{ width: 22, alignItems: 'center' }}>{icon}</View>
      <View style={{ flex: 1 }}>
        <Text style={[type.body, { color: c.text }]}>{phase.label}</Text>
        {phase.detail ? <Text style={[type.small, { color: phase.status === 'error' ? riskColors.HIGH : c.textMuted }]}>{phase.detail}</Text> : null}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  summary: { flexDirection: 'row', gap: space.sm },
  stat: { flex: 1, alignItems: 'center', paddingVertical: space.md, borderRadius: 14, borderWidth: StyleSheet.hairlineWidth },
  phase: { flexDirection: 'row', alignItems: 'center', gap: space.md, paddingVertical: space.md },
  step: { flexDirection: 'row', gap: space.md, alignItems: 'flex-start' },
  stepNum: { width: 22, height: 22, borderRadius: 11, alignItems: 'center', justifyContent: 'center' },
});
