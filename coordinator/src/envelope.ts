import { decodeB64Url, utf8 } from "./bytes";
import { protocol, type ServerError } from "./protocol";

export function checkEnvelope(raw: string): ServerError | null {
  if (utf8(raw).byteLength > protocol.envelope.max_bytes) return "too_large";
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return "bad_request";
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return "unsupported_version";
  const record = parsed as Record<string, unknown>;
  const keys = Object.keys(record);
  if (keys.length !== protocol.envelope.fields.length) return "unsupported_version";
  for (const field of protocol.envelope.fields) {
    if (!Object.hasOwn(record, field)) return "unsupported_version";
  }
  if (record.v !== protocol.version) return "unsupported_version";
  if (record.kdf !== protocol.envelope.kdf) return "unsupported_version";
  if (record.aead !== protocol.envelope.aead) return "unsupported_version";
  if (record.m !== protocol.envelope.m) return "unsupported_version";
  if (record.t !== protocol.envelope.t) return "unsupported_version";
  if (record.p !== protocol.envelope.p) return "unsupported_version";
  if (typeof record.salt !== "string" || typeof record.nonce !== "string" || typeof record.ct !== "string") {
    return "bad_request";
  }
  const salt = decodeB64Url(record.salt);
  const nonce = decodeB64Url(record.nonce);
  const ct = decodeB64Url(record.ct);
  if (!salt || salt.length !== protocol.envelope.salt_bytes) return "bad_request";
  if (!nonce || nonce.length !== protocol.envelope.nonce_bytes) return "bad_request";
  if (!ct || ct.length <= protocol.envelope.tag_bytes) return "bad_request";
  return null;
}
