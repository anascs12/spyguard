import { CameraView, useCameraPermissions } from 'expo-camera';
import * as Haptics from 'expo-haptics';
import { useState } from 'react';
import { Alert, Modal, Pressable, StyleSheet, Switch, Text, TextInput, View } from 'react-native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';

import { fetchLaptopResults, parseLink } from '@/detect/laptop';
import { disableScheduledScans, enableScheduledScans } from '@/detect/scheduled';
import { compareRooms, getSuspiciousDevices, saveRoomScan, setState, useStore } from '@/state/store';
import { Button, Card, Icon, Screen, SectionTitle } from '@/ui/components';
import { radius, riskColors, space, type, usePalette } from '@/ui/theme';

export default function SettingsScreen() {
  const c = usePalette();
  const laptop = useStore((s) => s.laptop);
  const trusted = useStore((s) => s.trusted);
  const known = useStore((s) => s.known);
  const [linkText, setLinkText] = useState('');
  const [status, setStatus] = useState<{ ok: boolean; text: string } | null>(null);
  const [scanning, setScanning] = useState(false);

  const connect = async (text: string) => {
    const link = parseLink(text);
    if (!link) {
      setStatus({ ok: false, text: 'That isn’t a privacyscanner:// link' });
      return;
    }
    setStatus({ ok: true, text: 'Connecting…' });
    try {
      const { findings } = await fetchLaptopResults(link);
      setState({ laptop: link });
      setLinkText('');
      setStatus({ ok: true, text: `Linked · ${findings.length} devices in the latest laptop scan` });
      Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success);
    } catch (e) {
      setStatus({ ok: false, text: e instanceof Error ? e.message : String(e) });
    }
  };

  const trustedEntries = Object.entries(trusted);
  const networks = Object.keys(known).length;

  return (
    <Screen title="Settings">
      <SectionTitle>Laptop scanner</SectionTitle>
      <Card>
        {laptop ? (
          <>
            <View style={styles.linked}>
              <Icon name="laptop" size={22} color={riskColors.LOW} />
              <View style={{ flex: 1 }}>
                <Text style={[type.body, { color: c.text, fontWeight: '600' }]}>Linked</Text>
                <Text style={[type.mono, { color: c.textMuted }]}>{laptop.host}:{laptop.port}</Text>
              </View>
            </View>
            <Text style={[type.small, { color: c.textMuted, marginVertical: space.md, lineHeight: 19 }]}>
              Each phone scan also pulls the laptop’s results, including monitor-mode findings from other networks.
            </Text>
            <Button kind="secondary" icon="link-off" label="Unlink" onPress={() => (setState({ laptop: null }), setStatus(null))} />
          </>
        ) : (
          <>
            <Text style={[type.small, { color: c.textMuted, lineHeight: 19 }]}>
              On the laptop run{' '}
              <Text style={[type.mono, { color: c.text }]}>sudo python3 scripts/scan.py --serve</Text>
              , then scan the QR code it shows or paste its link.
            </Text>
            <TextInput
              value={linkText}
              onChangeText={setLinkText}
              placeholder="privacyscanner://link?…"
              placeholderTextColor={c.textFaint}
              autoCapitalize="none"
              autoCorrect={false}
              style={[styles.input, { color: c.text, backgroundColor: c.surfaceAlt, borderColor: c.border }]}
            />
            <View style={{ flexDirection: 'row', gap: space.sm }}>
              <View style={{ flex: 1 }}><Button kind="secondary" icon="qrcode-scan" label="Scan QR" onPress={() => setScanning(true)} /></View>
              <View style={{ flex: 1 }}><Button icon="link" label="Link" disabled={!linkText} onPress={() => connect(linkText)} /></View>
            </View>
          </>
        )}
        {status && (
          <Text style={[type.small, { color: status.ok ? c.textMuted : riskColors.HIGH, marginTop: space.md }]}>{status.text}</Text>
        )}
      </Card>

      <SectionTitle>Trusted devices</SectionTitle>
      <Card style={{ paddingVertical: trustedEntries.length ? space.xs : space.lg }}>
        {trustedEntries.length === 0 ? (
          <Text style={[type.small, { color: c.textMuted }]}>
            Mark your own phone, laptop or headphones as trusted from a finding, and they won’t be flagged again.
          </Text>
        ) : (
          trustedEntries.map(([id, label], i) => (
            <View key={id} style={[styles.trustRow, i < trustedEntries.length - 1 && { borderBottomWidth: StyleSheet.hairlineWidth, borderBottomColor: c.border }]}>
              <View style={{ flex: 1 }}>
                <Text style={[type.body, { color: c.text }]}>{label}</Text>
                <Text style={[type.mono, { color: c.textMuted, fontSize: 12 }]}>{id.replace(/^\w+:/, '')}</Text>
              </View>
              <Pressable
                hitSlop={12}
                onPress={() => setState((s) => {
                  const next = { ...s.trusted };
                  delete next[id];
                  return { trusted: next };
                })}
              >
                <Icon name="close-circle-outline" color={c.textFaint} />
              </Pressable>
            </View>
          ))
        )}
      </Card>

      <SectionTitle>Scheduled scans</SectionTitle>
      <ScheduledScansSection />

      <SectionTitle>Room comparison</SectionTitle>
      <RoomComparisonSection />

      <SectionTitle>Device timeline</SectionTitle>
      <DeviceTimelineSection />

      <SectionTitle>History</SectionTitle>
      <Card>
        <Text style={[type.small, { color: c.textMuted, marginBottom: space.md, lineHeight: 19 }]}>
          Devices are remembered per network, so new arrivals show up as NEW. {networks} network{networks === 1 ? '' : 's'} remembered.
        </Text>
        <Button kind="secondary" icon="history" label="Forget history" disabled={!networks} onPress={() => setState({ known: {} })} />
      </Card>

      <SectionTitle>What a phone can’t see</SectionTitle>
      <Card>
        {[
          'Devices talking on other WiFi networks (needs the laptop in monitor mode)',
          'Wired-only (Ethernet/PoE) and 4G cameras',
          'Audio-only bugs',
          'Powered-off cameras: use Lens and Magnet instead',
        ].map((t) => (
          <View key={t} style={styles.limit}>
            <Icon name="minus" size={16} color={c.textFaint} />
            <Text style={[type.small, { color: c.text, flex: 1, lineHeight: 19 }]}>{t}</Text>
          </View>
        ))}
        <Text style={[type.small, { color: c.textFaint, marginTop: space.md, lineHeight: 18 }]}>
          Every check is detection-only. The app never logs into devices or joins other networks.
        </Text>
      </Card>

      <QrScanner visible={scanning} onClose={() => setScanning(false)} onCode={(code) => (setScanning(false), connect(code))} />
    </Screen>
  );
}

function ScheduledScansSection() {
  const c = usePalette();
  const schedule = useStore((s) => s.schedule);
  const [toggling, setToggling] = useState(false);

  const toggle = async (val: boolean) => {
    setToggling(true);
    try {
      if (val) {
        const ok = await enableScheduledScans(schedule.intervalMinutes);
        if (!ok) Alert.alert('Permission needed', 'Allow notifications and background activity to use scheduled scans.');
      } else {
        await disableScheduledScans();
      }
    } finally {
      setToggling(false);
    }
  };

  return (
    <Card>
      <View style={{ flexDirection: 'row', alignItems: 'center', justifyContent: 'space-between' }}>
        <View style={{ flex: 1 }}>
          <Text style={[type.body, { color: c.text, fontWeight: '600' }]}>Auto-scan</Text>
          <Text style={[type.small, { color: c.textMuted, lineHeight: 18 }]}>
            Scan every {schedule.intervalMinutes} min and notify on new devices
          </Text>
        </View>
        <Switch
          value={schedule.enabled}
          disabled={toggling}
          onValueChange={toggle}
          trackColor={{ true: c.accent }}
        />
      </View>
      {schedule.enabled && schedule.nextRun && (
        <Text style={[type.small, { color: c.textMuted, marginTop: space.sm }]}>
          Next scan ~{new Date(schedule.nextRun).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
        </Text>
      )}
      {schedule.enabled && (
        <View style={{ flexDirection: 'row', gap: space.sm, marginTop: space.md }}>
          {[30, 60, 120].map((m) => (
            <View key={m} style={{ flex: 1 }}>
              <Button
                kind={schedule.intervalMinutes === m ? 'primary' : 'secondary'}
                label={m < 60 ? `${m}m` : `${m / 60}h`}
                onPress={async () => {
                  await disableScheduledScans();
                  await enableScheduledScans(m);
                }}
              />
            </View>
          ))}
        </View>
      )}
    </Card>
  );
}

function RoomComparisonSection() {
  const c = usePalette();
  const rooms = useStore((s) => s.rooms);
  const findings = useStore((s) => s.findings);
  const [roomName, setRoomName] = useState('');

  const singles = rooms.length >= 2 ? compareRooms() : [];

  return (
    <Card>
      <Text style={[type.small, { color: c.textMuted, lineHeight: 19 }]}>
        Save a scan per room to find devices that appear in only one — more suspicious than those seen everywhere.
      </Text>
      <View style={{ flexDirection: 'row', gap: space.sm, marginTop: space.md }}>
        <TextInput
          value={roomName}
          onChangeText={setRoomName}
          placeholder="Room name…"
          placeholderTextColor={c.textFaint}
          style={[styles.input, { color: c.text, backgroundColor: c.surfaceAlt, borderColor: c.border, flex: 1, marginVertical: 0 }]}
        />
        <Button
          label="Save"
          icon="content-save-outline"
          disabled={!roomName || findings.length === 0}
          onPress={() => { saveRoomScan(roomName.trim()); setRoomName(''); Haptics.notificationAsync(Haptics.NotificationFeedbackType.Success); }}
        />
      </View>
      {rooms.length > 0 && (
        <View style={{ marginTop: space.md }}>
          {rooms.map((r) => (
            <View key={r.room} style={{ flexDirection: 'row', alignItems: 'center', gap: space.sm, marginTop: space.xs }}>
              <Icon name="door" size={16} color={c.textMuted} />
              <Text style={[type.small, { color: c.text, flex: 1 }]}>{r.room}</Text>
              <Text style={[type.caption, { color: c.textMuted }]}>{r.findingIds.length} devices</Text>
            </View>
          ))}
        </View>
      )}
      {singles.length > 0 && (
        <View style={{ marginTop: space.md, paddingTop: space.md, borderTopWidth: StyleSheet.hairlineWidth, borderTopColor: c.border }}>
          <Text style={[type.body, { color: riskColors.HIGH, fontWeight: '600' }]}>
            {singles.length} device{singles.length > 1 ? 's' : ''} in only one room
          </Text>
          {singles.map((s) => (
            <Text key={s.id} style={[type.small, { color: c.text, marginTop: space.xs }]}>
              {s.id.replace(/^\w+:/, '')} — only in {s.onlyIn}
            </Text>
          ))}
        </View>
      )}
      {rooms.length >= 2 && singles.length === 0 && (
        <Text style={[type.small, { color: riskColors.LOW, marginTop: space.md }]}>
          All devices appear in every room (likely infrastructure).
        </Text>
      )}
    </Card>
  );
}

function DeviceTimelineSection() {
  const c = usePalette();
  const timeline = useStore((s) => s.timeline);
  const deviceTimelines = useStore((s) => s.deviceTimelines);

  const suspicious = timeline.length >= 3 ? getSuspiciousDevices() : [];
  const deviceCount = Object.keys(deviceTimelines).length;

  return (
    <Card>
      <Text style={[type.small, { color: c.textMuted, lineHeight: 19 }]}>
        Each scan records a timeline snapshot. Over multiple scans, devices with
        suspicious patterns (intermittent, night-only) are flagged.
      </Text>
      <View style={{ flexDirection: 'row', gap: space.lg, marginTop: space.md }}>
        <View style={{ alignItems: 'center' }}>
          <Text style={[type.body, { color: c.text, fontWeight: '700', fontSize: 20 }]}>{timeline.length}</Text>
          <Text style={[type.caption, { color: c.textMuted }]}>snapshots</Text>
        </View>
        <View style={{ alignItems: 'center' }}>
          <Text style={[type.body, { color: c.text, fontWeight: '700', fontSize: 20 }]}>{deviceCount}</Text>
          <Text style={[type.caption, { color: c.textMuted }]}>devices tracked</Text>
        </View>
      </View>
      {suspicious.length > 0 && (
        <View style={{ marginTop: space.md, paddingTop: space.md, borderTopWidth: StyleSheet.hairlineWidth, borderTopColor: c.border }}>
          <Text style={[type.body, { color: riskColors.HIGH, fontWeight: '600' }]}>
            {suspicious.length} device{suspicious.length > 1 ? 's' : ''} with unusual patterns
          </Text>
          {suspicious.map((s) => (
            <View key={s.id} style={{ marginTop: space.sm }}>
              <Text style={[type.small, { color: c.text }]}>{s.id.replace(/^\w+:/, '')}</Text>
              {s.reasons.map((r) => (
                <Text key={r} style={[type.caption, { color: riskColors.MODERATE, marginLeft: space.sm }]}>
                  {r}
                </Text>
              ))}
            </View>
          ))}
        </View>
      )}
      {timeline.length >= 3 && suspicious.length === 0 && (
        <Text style={[type.small, { color: riskColors.LOW, marginTop: space.md }]}>
          No suspicious activity patterns detected.
        </Text>
      )}
      {timeline.length > 0 && (
        <View style={{ marginTop: space.md }}>
          <Button
            kind="secondary" icon="delete-outline" label="Clear timeline"
            onPress={() => {
              Alert.alert('Clear timeline?', 'All timeline data will be erased.', [
                { text: 'Cancel' },
                { text: 'Clear', style: 'destructive', onPress: () => setState({ timeline: [], deviceTimelines: {} }) },
              ]);
            }}
          />
        </View>
      )}
    </Card>
  );
}

function QrScanner({ visible, onClose, onCode }: { visible: boolean; onClose: () => void; onCode: (code: string) => void }) {
  const [permission, requestPermission] = useCameraPermissions();
  const insets = useSafeAreaInsets();
  if (!visible) return null;
  return (
    <Modal visible animationType="slide" onRequestClose={onClose}>
      <View style={{ flex: 1, backgroundColor: '#000' }}>
        {permission?.granted ? (
          <CameraView
            style={StyleSheet.absoluteFill}
            barcodeScannerSettings={{ barcodeTypes: ['qr'] }}
            onBarcodeScanned={({ data }) => data.startsWith('privacyscanner://') && onCode(data)}
          />
        ) : (
          <View style={styles.qrPerm}>
            <Button label="Allow camera" icon="camera" onPress={requestPermission} />
          </View>
        )}
        <View pointerEvents="none" style={styles.qrFrame} />
        <View style={[styles.qrClose, { top: insets.top + space.md }]}>
          <Button kind="secondary" icon="close" label="Close" onPress={onClose} />
        </View>
      </View>
    </Modal>
  );
}

const styles = StyleSheet.create({
  linked: { flexDirection: 'row', alignItems: 'center', gap: space.md },
  input: {
    height: 46, borderRadius: radius.md, borderWidth: StyleSheet.hairlineWidth, paddingHorizontal: space.md,
    marginVertical: space.md, fontFamily: 'monospace', fontSize: 13,
  },
  trustRow: { flexDirection: 'row', alignItems: 'center', paddingVertical: space.md },
  limit: { flexDirection: 'row', gap: space.sm, marginTop: space.xs },
  qrPerm: { flex: 1, justifyContent: 'center', padding: space.xl },
  qrFrame: {
    position: 'absolute', alignSelf: 'center', top: '30%', width: 240, height: 240,
    borderWidth: 3, borderColor: '#fff', borderRadius: 24,
  },
  qrClose: { position: 'absolute', right: space.lg },
});
