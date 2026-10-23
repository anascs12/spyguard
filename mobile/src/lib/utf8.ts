/** Decode a latin-1 string (one char per byte) holding UTF-8 bytes. Hermes lacks TextDecoder. */
export function latin1ToUtf8(raw: string): string {
  let out = '';
  for (let i = 0; i < raw.length; ) {
    const b = raw.charCodeAt(i++);
    if (b < 0x80) {
      out += String.fromCharCode(b);
      continue;
    }
    const extra = b >= 0xf0 ? 3 : b >= 0xe0 ? 2 : b >= 0xc0 ? 1 : 0;
    let cp = b & (0x3f >> extra);
    for (let k = 0; k < extra && i < raw.length; k++) cp = (cp << 6) | (raw.charCodeAt(i++) & 0x3f);
    out += String.fromCodePoint(extra ? cp : 0xfffd);
  }
  return out;
}
