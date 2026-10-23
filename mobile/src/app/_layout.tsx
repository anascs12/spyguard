import { useURL } from 'expo-linking';
import { DarkTheme, DefaultTheme, ThemeProvider } from 'expo-router';
import { NativeTabs } from 'expo-router/native-tabs';
import { StatusBar } from 'expo-status-bar';
import { useEffect } from 'react';
import { useColorScheme } from 'react-native';

import { loadDemo } from '@/state/demo';
import { hydrate } from '@/state/store';
import { usePalette } from '@/ui/theme';

export default function RootLayout() {
  const scheme = useColorScheme();
  const c = usePalette();
  const url = useURL();
  useEffect(() => {
    hydrate();
  }, []);
  useEffect(() => {
    if (url && /[?&]demo=1\b/.test(url)) loadDemo();
  }, [url]);

  const base = scheme === 'light' ? DefaultTheme : DarkTheme;
  return (
    <ThemeProvider value={{ ...base, colors: { ...base.colors, background: c.bg, card: c.surface, primary: c.accent } }}>
      <StatusBar style={scheme === 'light' ? 'dark' : 'light'} />
      <NativeTabs tintColor={c.accent} backgroundColor={c.surface} labelStyle={{ color: c.textMuted }}>
        <NativeTabs.Trigger name="index">
          <NativeTabs.Trigger.Icon sf="dot.radiowaves.left.and.right" md="radar" />
          <NativeTabs.Trigger.Label>Scan</NativeTabs.Trigger.Label>
        </NativeTabs.Trigger>
        <NativeTabs.Trigger name="find">
          <NativeTabs.Trigger.Icon sf="location.fill" md="my_location" />
          <NativeTabs.Trigger.Label>Find</NativeTabs.Trigger.Label>
        </NativeTabs.Trigger>
        <NativeTabs.Trigger name="lens">
          <NativeTabs.Trigger.Icon sf="camera.viewfinder" md="center_focus_strong" />
          <NativeTabs.Trigger.Label>Lens</NativeTabs.Trigger.Label>
        </NativeTabs.Trigger>
        <NativeTabs.Trigger name="heatmap">
          <NativeTabs.Trigger.Icon sf="map" md="layers" />
          <NativeTabs.Trigger.Label>Heatmap</NativeTabs.Trigger.Label>
        </NativeTabs.Trigger>
        <NativeTabs.Trigger name="thermal">
          <NativeTabs.Trigger.Icon sf="thermometer" md="thermostat" />
          <NativeTabs.Trigger.Label>Thermal</NativeTabs.Trigger.Label>
        </NativeTabs.Trigger>
        <NativeTabs.Trigger name="magnet">
          <NativeTabs.Trigger.Icon sf="safari" md="explore" />
          <NativeTabs.Trigger.Label>Magnet</NativeTabs.Trigger.Label>
        </NativeTabs.Trigger>
        <NativeTabs.Trigger name="settings">
          <NativeTabs.Trigger.Icon sf="gearshape" md="settings" />
          <NativeTabs.Trigger.Label>Settings</NativeTabs.Trigger.Label>
        </NativeTabs.Trigger>
      </NativeTabs>
    </ThemeProvider>
  );
}
