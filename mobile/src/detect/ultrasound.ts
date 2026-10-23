import { Audio } from 'expo-av';

import type { Finding } from './types';

const SAMPLE_RATE = 44100;
const FFT_SIZE = 4096;
const ULTRASONIC_MIN_HZ = 18000;
const ULTRASONIC_MAX_HZ = 22000;
const DETECTION_THRESHOLD_DB = -40;
const RECORD_DURATION_MS = 10000;

export interface UltrasoundResult {
  detected: boolean;
  peakFrequency: number | null;
  peakAmplitude: number | null;
  spectralPeaks: { hz: number; db: number }[];
}

function hannWindow(size: number): Float32Array {
  const w = new Float32Array(size);
  for (let i = 0; i < size; i++) {
    w[i] = 0.5 * (1 - Math.cos((2 * Math.PI * i) / (size - 1)));
  }
  return w;
}

function realFFT(samples: Float32Array): Float32Array {
  const n = samples.length;
  const magnitudes = new Float32Array(n / 2);

  for (let k = 0; k < n / 2; k++) {
    let real = 0;
    let imag = 0;
    for (let t = 0; t < n; t++) {
      const angle = (2 * Math.PI * k * t) / n;
      real += samples[t] * Math.cos(angle);
      imag -= samples[t] * Math.sin(angle);
    }
    magnitudes[k] = Math.sqrt(real * real + imag * imag) / n;
  }
  return magnitudes;
}

function magnitudeToDb(mag: number): number {
  return mag > 0 ? 20 * Math.log10(mag) : -120;
}

function analyzeSpectrum(pcmData: Float32Array): UltrasoundResult {
  const window = hannWindow(FFT_SIZE);
  const windowed = new Float32Array(FFT_SIZE);

  const numFrames = Math.floor(pcmData.length / FFT_SIZE);
  const avgMagnitudes = new Float32Array(FFT_SIZE / 2);

  for (let frame = 0; frame < numFrames; frame++) {
    const offset = frame * FFT_SIZE;
    for (let i = 0; i < FFT_SIZE; i++) {
      windowed[i] = (pcmData[offset + i] ?? 0) * window[i];
    }
    const mags = realFFT(windowed);
    for (let i = 0; i < mags.length; i++) {
      avgMagnitudes[i] += mags[i] / numFrames;
    }
  }

  const hzPerBin = SAMPLE_RATE / FFT_SIZE;
  const minBin = Math.floor(ULTRASONIC_MIN_HZ / hzPerBin);
  const maxBin = Math.ceil(ULTRASONIC_MAX_HZ / hzPerBin);

  const spectralPeaks: { hz: number; db: number }[] = [];
  let peakFrequency: number | null = null;
  let peakAmplitude: number | null = null;
  let peakDb = -120;

  for (let bin = minBin; bin <= maxBin && bin < avgMagnitudes.length; bin++) {
    const db = magnitudeToDb(avgMagnitudes[bin]);
    const hz = Math.round(bin * hzPerBin);

    if (db > DETECTION_THRESHOLD_DB) {
      spectralPeaks.push({ hz, db: Math.round(db * 10) / 10 });
      if (db > peakDb) {
        peakDb = db;
        peakFrequency = hz;
        peakAmplitude = Math.round(db * 10) / 10;
      }
    }
  }

  return {
    detected: spectralPeaks.length > 0,
    peakFrequency,
    peakAmplitude,
    spectralPeaks,
  };
}

export async function scanUltrasound(): Promise<UltrasoundResult> {
  const { status } = await Audio.requestPermissionsAsync();
  if (status !== 'granted') {
    return { detected: false, peakFrequency: null, peakAmplitude: null, spectralPeaks: [] };
  }

  await Audio.setAudioModeAsync({
    allowsRecordingIOS: true,
    playsInSilentModeIOS: true,
  });

  const recording = new Audio.Recording();
  await recording.prepareToRecordAsync({
    android: {
      extension: '.wav',
      outputFormat: Audio.AndroidOutputFormat.DEFAULT,
      audioEncoder: Audio.AndroidAudioEncoder.DEFAULT,
      sampleRate: SAMPLE_RATE,
      numberOfChannels: 1,
      bitRate: 256000,
    },
    ios: {
      extension: '.wav',
      outputFormat: Audio.IOSOutputFormat.LINEARPCM,
      audioQuality: Audio.IOSAudioQuality.MAX,
      sampleRate: SAMPLE_RATE,
      numberOfChannels: 1,
      bitRate: 256000,
      linearPCMBitDepth: 16,
      linearPCMIsBigEndian: false,
      linearPCMIsFloat: false,
    },
    web: { mimeType: 'audio/wav', bitsPerSecond: 256000 },
  });

  await recording.startAsync();
  await new Promise((r) => setTimeout(r, RECORD_DURATION_MS));
  await recording.stopAndUnloadAsync();

  const uri = recording.getURI();
  if (!uri) {
    return { detected: false, peakFrequency: null, peakAmplitude: null, spectralPeaks: [] };
  }

  // Read WAV file and extract PCM samples
  const response = await fetch(uri);
  const buffer = await response.arrayBuffer();
  const view = new DataView(buffer);

  // Skip WAV header (44 bytes for standard PCM WAV)
  const pcmStart = 44;
  const sampleCount = (buffer.byteLength - pcmStart) / 2;
  const pcm = new Float32Array(sampleCount);

  for (let i = 0; i < sampleCount; i++) {
    const sample = view.getInt16(pcmStart + i * 2, true);
    pcm[i] = sample / 32768;
  }

  await Audio.setAudioModeAsync({ allowsRecordingIOS: false });

  return analyzeSpectrum(pcm);
}

export function classifyUltrasound(result: UltrasoundResult): Finding[] {
  if (!result.detected || !result.peakFrequency) return [];

  const findings: Finding[] = [];
  const numPeaks = result.spectralPeaks.length;
  const risk = numPeaks >= 3 ? 'HIGH' : numPeaks >= 1 ? 'MODERATE' : 'LOW';

  findings.push({
    id: `ultrasound:${result.peakFrequency}`,
    risk,
    source: 'ultrasound' as any,
    address: `${result.peakFrequency} Hz`,
    title: 'Ultrasonic beacon detected',
    manufacturer: 'Unknown',
    evidence:
      `${numPeaks} peak(s) in 18-22 kHz range. ` +
      `Strongest: ${result.peakFrequency} Hz at ${result.peakAmplitude} dB. ` +
      `Ultrasonic beacons are used by some tracking and surveillance devices.`,
    recommendation:
      'Move around the room while scanning. The beacon is likely near the ' +
      'position where the signal is strongest. Ultrasonic emitters can be ' +
      'hidden in speakers, smoke detectors, or power adapters.',
  });

  return findings;
}
