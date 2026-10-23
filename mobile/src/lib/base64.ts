const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const LOOKUP = new Uint8Array(128);
for (let i = 0; i < ALPHABET.length; i++) LOOKUP[ALPHABET.charCodeAt(i)] = i;

/** Decode standard base64 (padding optional) without relying on atob/Buffer. */
export function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.replace(/[^A-Za-z0-9+/]/g, '');
  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let o = 0;
  for (let i = 0; i < clean.length; i += 4) {
    const n =
      (LOOKUP[clean.charCodeAt(i)] << 18) |
      (LOOKUP[clean.charCodeAt(i + 1)] << 12) |
      ((LOOKUP[clean.charCodeAt(i + 2)] ?? 0) << 6) |
      (LOOKUP[clean.charCodeAt(i + 3)] ?? 0);
    out[o++] = (n >> 16) & 0xff;
    if (i + 2 < clean.length) out[o++] = (n >> 8) & 0xff;
    if (i + 3 < clean.length) out[o++] = n & 0xff;
  }
  return out.slice(0, o);
}
