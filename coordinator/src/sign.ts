import { concat, sha256, uint64be, utf8 } from "./bytes";
import { protocol, type SignatureName } from "./protocol";

export interface SignValues {
  origin?: string;
  server_nonce?: Uint8Array;
  nonce?: Uint8Array;
  receiver_pubkey?: Uint8Array;
  pubkey?: Uint8Array;
  session_hash?: Uint8Array;
  ticket_hash?: Uint8Array;
  issuer_hash?: Uint8Array;
  counter?: number;
  envelope_sha256?: Uint8Array;
  request_digest?: Uint8Array;
}

interface SignatureSpec {
  scope: string;
  method?: string;
  path?: string;
  sign_fields?: readonly string[];
  digest_fields: readonly string[];
}

function specOf(name: SignatureName): SignatureSpec {
  return protocol.signatures[name];
}

function fieldBytes(name: string, spec: SignatureSpec, values: SignValues): Uint8Array {
  if (name === "0x00") return new Uint8Array([0]);
  if (name === "0x01") return new Uint8Array([1]);
  if (name === "scope") return utf8(spec.scope);
  if (name === "method") return utf8(spec.method ?? "");
  if (name === "path") return utf8(spec.path ?? "");
  if (name === "origin") return utf8(values.origin ?? "");
  if (name === "counter") return uint64be(values.counter ?? 0);
  if (name === "server_nonce" && values.server_nonce) return values.server_nonce;
  if (name === "nonce" && values.nonce) return values.nonce;
  if (name === "receiver_pubkey" && values.receiver_pubkey) return values.receiver_pubkey;
  if (name === "pubkey" && values.pubkey) return values.pubkey;
  if (name === "session_hash" && values.session_hash) return values.session_hash;
  if (name === "ticket_hash" && values.ticket_hash) return values.ticket_hash;
  if (name === "issuer_hash" && values.issuer_hash) return values.issuer_hash;
  if (name === "envelope_sha256" && values.envelope_sha256) return values.envelope_sha256;
  if (name === "request_digest" && values.request_digest) return values.request_digest;
  throw new Error("signature-field");
}

export async function requestDigest(name: SignatureName, values: SignValues): Promise<Uint8Array> {
  const spec = specOf(name);
  const parts = spec.digest_fields.map((field) => fieldBytes(field, spec, values));
  return sha256(concat(parts));
}

export async function signedMessage(name: SignatureName, values: SignValues): Promise<Uint8Array> {
  const spec = specOf(name);
  const digest = await requestDigest(name, values);
  if (!spec.sign_fields) return digest;
  const withDigest: SignValues = { ...values, request_digest: digest };
  const parts = spec.sign_fields.map((field) => fieldBytes(field, spec, withDigest));
  return concat(parts);
}

export async function verifySignature(
  name: SignatureName,
  values: SignValues,
  pubkey: Uint8Array,
  signature: Uint8Array,
): Promise<boolean> {
  const message = await signedMessage(name, values);
  const key = await crypto.subtle.importKey("raw", new Uint8Array(pubkey), { name: "Ed25519" }, false, [
    "verify",
  ]);
  return crypto.subtle.verify({ name: "Ed25519" }, key, new Uint8Array(signature), message);
}

export async function signBytes(
  name: SignatureName,
  values: SignValues,
  privateKey: CryptoKey,
): Promise<Uint8Array> {
  const message = await signedMessage(name, values);
  return new Uint8Array(await crypto.subtle.sign({ name: "Ed25519" }, privateKey, message));
}
