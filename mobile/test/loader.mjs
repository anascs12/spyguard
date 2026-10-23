// Resolve the app's path aliases and extensionless TS imports for `node --test`,
// and swap native-only modules for stubs.
import { existsSync } from 'node:fs';
import { register } from 'node:module';
import { dirname, resolve as resolvePath } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

if (!globalThis.__aliasHookRegistered) {
  globalThis.__aliasHookRegistered = true;
  register(import.meta.url);
}

const ROOT = resolvePath(dirname(fileURLToPath(import.meta.url)), '..');
const STUBS = {
  '@modules/privacy-native': 'test/stubs/privacy-native.ts',
  'react-native-ble-plx': 'test/stubs/ble-plx.ts',
};

function withExtension(path) {
  const candidates = /\.(ts|tsx|json|mjs|js)$/.test(path) ? [path] : [`${path}.ts`, `${path}.tsx`, `${path}/index.ts`];
  return candidates.find((c) => existsSync(c)) ?? null;
}

export async function resolve(specifier, context, next) {
  let path = null;
  if (STUBS[specifier]) path = resolvePath(ROOT, STUBS[specifier]);
  else if (specifier.startsWith('@/')) path = withExtension(resolvePath(ROOT, 'src', specifier.slice(2)));
  else if (specifier.startsWith('.') && context.parentURL?.startsWith('file:')) {
    path = withExtension(resolvePath(dirname(fileURLToPath(context.parentURL)), specifier));
  }
  if (path) {
    const url = pathToFileURL(path).href;
    return path.endsWith('.json')
      ? { url, format: 'json', importAttributes: { type: 'json' }, shortCircuit: true }
      : { url, shortCircuit: true };
  }
  return next(specifier, context);
}
