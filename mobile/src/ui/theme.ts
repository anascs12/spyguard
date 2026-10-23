import { useColorScheme } from 'react-native';

import type { Risk } from '@/detect/types';

const dark = {
  bg: '#0B0D10',
  surface: '#14171C',
  surfaceAlt: '#1B1F26',
  border: '#242A33',
  text: '#ECEEF1',
  textMuted: '#8A93A3',
  textFaint: '#5B6472',
  accent: '#6C8CFF',
  accentText: '#FFFFFF',
  overlay: 'rgba(0,0,0,0.6)',
};

const light: typeof dark = {
  bg: '#F6F7F9',
  surface: '#FFFFFF',
  surfaceAlt: '#EEF0F3',
  border: '#E1E4E9',
  text: '#11141A',
  textMuted: '#5E6675',
  textFaint: '#9AA2AF',
  accent: '#3E63F2',
  accentText: '#FFFFFF',
  overlay: 'rgba(0,0,0,0.35)',
};

export type Palette = typeof dark;

export const riskColors: Record<Risk, string> = {
  CRITICAL: '#FF4D4F',
  HIGH: '#FF8A3D',
  MODERATE: '#E9B730',
  LOW: '#33C481',
  INFO: '#7C93FF',
};

export const riskLabels: Record<Risk, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MODERATE: 'Check',
  LOW: 'Low',
  INFO: 'Safe',
};

export const space = { xs: 4, sm: 8, md: 12, lg: 16, xl: 24, xxl: 32 };
export const radius = { sm: 8, md: 12, lg: 18, pill: 999 };
export const type = {
  title: { fontSize: 28, fontWeight: '700' as const, letterSpacing: -0.5 },
  heading: { fontSize: 17, fontWeight: '600' as const },
  body: { fontSize: 15 },
  small: { fontSize: 13 },
  caption: { fontSize: 11, fontWeight: '600' as const, letterSpacing: 0.6 },
  mono: { fontSize: 13, fontFamily: 'monospace' },
};

export function usePalette(): Palette {
  return useColorScheme() === 'light' ? light : dark;
}
