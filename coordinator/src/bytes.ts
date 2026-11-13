import { protocol } from "./protocol";

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function utf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

export function concat(parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.length;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export function bytesEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let diff = 0;
  for (let i = 0; i < left.length; i++) diff |= left[i] ^ right[i];
  return diff === 0;
}

export function uint64be(value: number): Uint8Array {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("counter");
  }
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), false);
  return out;
}

export function encodeB64Url(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i] ?? 0;
    const b = i + 1 < bytes.length ? (bytes[i + 1] ?? 0) : 0;
    const c = i + 2 < bytes.length ? (bytes[i + 2] ?? 0) : 0;
    const triple = (a << 16) | (b << 8) | c;
    out += B64[(triple >> 18) & 63];
    out += B64[(triple >> 12) & 63];
    if (i + 1 < bytes.length) out += B64[(triple >> 6) & 63];
    if (i + 2 < bytes.length) out += B64[triple & 63];
  }
  return out;
}

export function decodeB64Url(value: string): Uint8Array | null {
  if (value.length === 0 || value.length % 4 === 1) return null;
  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of value) {
    const index = B64.indexOf(char);
    if (index < 0) return null;
    buffer = (buffer << 6) | index;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >> bits) & 0xff);
    }
  }
  return Uint8Array.from(bytes);
}

export function encodeHex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}

export function decodeHex(value: string): Uint8Array | null {
  if (value.length % 2 !== 0 || !/^[0-9a-f]+$/.test(value)) return null;
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

export async function sha256(data: Uint8Array): Promise<Uint8Array> {
  const copy = new Uint8Array(data);
  return new Uint8Array(await crypto.subtle.digest("SHA-256", copy));
}

export async function fingerprint(pubkey: Uint8Array): Promise<string> {
  const hash = encodeHex(await sha256(pubkey)).slice(0, protocol.fingerprint.bytes * 2);
  const groups: string[] = [];
  const size = protocol.fingerprint.group_hex;
  for (let i = 0; i < hash.length; i += size) groups.push(hash.slice(i, i + size));
  return groups.join(protocol.fingerprint.separator);
}

export function originFromUrl(url: URL): string {
  const scheme = url.protocol.replace(/:$/, "");
  const port = url.port || (scheme === "https" ? "443" : "80");
  const host = url.hostname.includes(":") ? `[${url.hostname}]` : url.hostname;
  return `${scheme}://${host}:${port}`;
}
