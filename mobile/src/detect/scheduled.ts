import { getState, setState } from '@/state/store';

import { scanBle, classifyBle } from './ble';
import { networkInfo, scanLan } from './lan';
import { classifyAccessPoints, scanAccessPoints } from './wifi';
import { RISK_ORDER, type Finding } from './types';

const TASK_NAME = 'spyguard-background-scan';

try {
  const Notifications = require('expo-notifications');
  Notifications.setNotificationHandler({
    handleNotification: async () => ({
      shouldShowAlert: true,
      shouldShowBanner: true,
      shouldShowList: true,
      shouldPlaySound: true,
      shouldSetBadge: true,
      priority: Notifications.AndroidNotificationPriority.HIGH,
    }),
  });

  const TaskManager = require('expo-task-manager');
  const BackgroundFetch = require('expo-background-fetch');
  TaskManager.defineTask(TASK_NAME, async () => {
    try {
      const { schedule } = getState();
      if (!schedule.enabled) return BackgroundFetch.BackgroundFetchResult.NoData;

      const findings: Finding[] = [];

      try {
        const aps = await scanAccessPoints();
        findings.push(...classifyAccessPoints(aps));
      } catch {}

      try {
        const adverts = await scanBle(6);
        findings.push(...classifyBle(adverts));
      } catch {}

      try {
        const net = networkInfo();
        if (net) {
          const lan = await scanLan(net, () => {});
          findings.push(...lan);
        }
      } catch {}

      if (findings.length === 0) {
        return BackgroundFetch.BackgroundFetchResult.NoData;
      }

      const net = networkInfo();
      const networkId = net ? `${net.gateway}/${net.prefixLength}` : 'unknown';
      const known = new Set(getState().known[networkId] ?? []);
      const newFindings = findings.filter(
        (f) => !known.has(f.id) && f.risk !== 'INFO' && f.risk !== 'LOW',
      );

      findings.forEach((f) => known.add(f.id));
      setState((s) => ({
        known: { ...s.known, [networkId]: [...known] },
        lastScan: Date.now(),
        schedule: { ...s.schedule, nextRun: Date.now() + s.schedule.intervalMinutes * 60000 },
      }));

      if (newFindings.length > 0) {
        const worst = newFindings.sort(
          (a, b) => RISK_ORDER.indexOf(a.risk) - RISK_ORDER.indexOf(b.risk),
        )[0];
        await Notifications.scheduleNotificationAsync({
          content: {
            title: 'New device detected',
            body: `${worst.title} (${worst.risk}) — ${newFindings.length} new finding${newFindings.length > 1 ? 's' : ''}`,
            data: { type: 'scan-alert' },
            sound: true,
          },
          trigger: null,
        });
      }

      return BackgroundFetch.BackgroundFetchResult.NewData;
    } catch {
      return BackgroundFetch.BackgroundFetchResult.Failed;
    }
  });
} catch {}

export async function enableScheduledScans(intervalMinutes: number): Promise<boolean> {
  try {
    const Notifications = require('expo-notifications');
    const BackgroundFetch = require('expo-background-fetch');

    const { status: existing } = await Notifications.getPermissionsAsync();
    if (existing !== 'granted') {
      const { status } = await Notifications.requestPermissionsAsync();
      if (status !== 'granted') return false;
    }

    const bgStatus = await BackgroundFetch.getStatusAsync();
    if (bgStatus === BackgroundFetch.BackgroundFetchStatus.Denied) return false;

    await BackgroundFetch.registerTaskAsync(TASK_NAME, {
      minimumInterval: intervalMinutes * 60,
      stopOnTerminate: false,
      startOnBoot: true,
    });

    setState({
      schedule: {
        enabled: true,
        intervalMinutes,
        nextRun: Date.now() + intervalMinutes * 60000,
      },
    });

    return true;
  } catch {
    return false;
  }
}

export async function disableScheduledScans(): Promise<void> {
  try {
    const TaskManager = require('expo-task-manager');
    const BackgroundFetch = require('expo-background-fetch');
    const registered = await TaskManager.isTaskRegisteredAsync(TASK_NAME);
    if (registered) await BackgroundFetch.unregisterTaskAsync(TASK_NAME);
  } catch {}
  setState({ schedule: { enabled: false, intervalMinutes: 60, nextRun: null } });
}
