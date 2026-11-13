import { errorStatus, protocol, type ServerError } from "./protocol";

export async function readBody(request: Request): Promise<{ text: string } | { error: ServerError }> {
  const max = protocol.limits.request_max_bytes;
  const declared = request.headers.get("content-length");
  if (declared && Number(declared) > max) return { error: "too_large" };
  if (!request.body) return { error: "bad_request" };
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const step = await reader.read();
    if (step.done) break;
    total += step.value.byteLength;
    if (total > max) {
      await reader.cancel();
      return { error: "too_large" };
    }
    chunks.push(step.value);
  }
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return { text: new TextDecoder().decode(merged) };
}

export function jsonResponse(body: unknown, status: number): Response {
  return Response.json(body, {
    status,
    headers: { "cache-control": protocol.http.cache_control },
  });
}

export function errorResponse(error: ServerError, status = errorStatus(error)): Response {
  return jsonResponse({ v: protocol.version, error }, status);
}

type Shape = { ok: true; value: Record<string, unknown> } | { ok: false; error: ServerError };

export function objectShape(value: unknown, keys: readonly string[]): Shape {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { ok: false, error: "bad_request" };
  }
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (!keys.includes(key)) return { ok: false, error: "unsupported_version" };
  }
  for (const key of keys) {
    if (!Object.hasOwn(record, key)) return { ok: false, error: "bad_request" };
  }
  if (record.v !== protocol.version) return { ok: false, error: "unsupported_version" };
  return { ok: true, value: record };
}

export function oneOf(value: unknown, variants: readonly (readonly string[])[]): Shape {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { ok: false, error: "bad_request" };
  }
  const record = value as Record<string, unknown>;
  const allowed = new Set(variants.flat());
  for (const key of Object.keys(record)) {
    if (!allowed.has(key)) return { ok: false, error: "unsupported_version" };
  }
  if (record.v !== protocol.version) return { ok: false, error: "unsupported_version" };
  const present = Object.keys(record);
  for (const keys of variants) {
    if (present.length === keys.length && keys.every((key) => Object.hasOwn(record, key))) {
      return { ok: true, value: record };
    }
  }
  return { ok: false, error: "bad_request" };
}

export function textField(record: Record<string, unknown>, key: string): string | null {
  const value = record[key];
  return typeof value === "string" ? value : null;
}

export function boolField(record: Record<string, unknown>, key: string): boolean | null {
  const value = record[key];
  return typeof value === "boolean" ? value : null;
}

export function intField(record: Record<string, unknown>, key: string): number | null {
  const value = record[key];
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}
