import { env, SELF, runInDurableObject } from "cloudflare:test";
import { decodeB64Url, decodeHex, encodeB64Url, encodeHex, sha256, utf8 } from "../src/bytes";
import { sourceObjectName } from "../src/gate";
import { protocol } from "../src/protocol";
import type { SessionDO } from "../src/session";
import { requestDigest, signBytes } from "../src/sign";
import type { TicketDO } from "../src/ticket";

export const ORIGIN = "http://127.0.0.1:8787";
export const PASSPHRASE = "example-passphrase-not-a-secret";
export const SHARE_URI =
  "hysteria2://example-auth-not-a-secret@192.0.2.1:443/?sni=example.invalid";
export const CIPHERTEXT = "example-ciphertext-not-a-secret";

export interface Receiver {
  raw: Uint8Array;
  b64: string;
  privateKey: CryptoKey;
}

export interface OpenedTicket {
  name: string;
  stub: DurableObjectStub<TicketDO>;
  ticket: string;
  issuer: string;
  envelope: string;
  expiresAt: number;
}

export interface OpenedSession {
  name: string;
  stub: DurableObjectStub<SessionDO>;
  capability: string;
}

export interface TicketDump {
  state: string | null;
  expires_at: number | null;
  envelope: string | null;
  op: number | null;
  bound_pubkey: string | null;
  seed_nonce: string | null;
  op_nonce: string | null;
  envelope_sha256: string | null;
  nonces: number;
  alarm: number | null;
}

let sourceOctet = 20;

export function nextSource(): string {
  sourceOctet += 1;
  if (sourceOctet > 230) throw new Error("source-space");
  return `192.0.2.${sourceOctet}`;
}

export function exampleBytes(label: string): Uint8Array {
  const text = `example-${label}-not-a-secret`;
  const encoded = utf8(text);
  if (encoded.length > protocol.capability_bytes) throw new Error("fixture-length");
  const out = new Uint8Array(protocol.capability_bytes);
  out.set(encoded);
  for (let i = encoded.length; i < out.length; i++) out[i] = 0x21;
  return out;
}

export function exampleEnvelope(ctText = CIPHERTEXT): string {
  const values: Record<string, unknown> = {
    v: protocol.version,
    kdf: protocol.envelope.kdf,
    m: protocol.envelope.m,
    t: protocol.envelope.t,
    p: protocol.envelope.p,
    salt: encodeB64Url(new Uint8Array(protocol.envelope.salt_bytes).fill(0x11)),
    aead: protocol.envelope.aead,
    nonce: encodeB64Url(new Uint8Array(protocol.envelope.nonce_bytes).fill(0x22)),
    ct: encodeB64Url(utf8(ctText)),
  };
  const ordered: Record<string, unknown> = {};
  for (const field of protocol.envelope.fields) {
    if (values[field] === undefined) throw new Error("envelope-field");
    ordered[field] = values[field];
  }
  return JSON.stringify(ordered);
}

export async function receiver(): Promise<Receiver> {
  const key = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  if (!("publicKey" in key)) throw new Error("keypair");
  const exported = await crypto.subtle.exportKey("raw", key.publicKey);
  const raw =
    exported instanceof ArrayBuffer
      ? new Uint8Array(exported)
      : exported instanceof Uint8Array
        ? new Uint8Array(exported)
        : null;
  if (!raw) throw new Error("pubkey");
  if (raw.length !== protocol.pubkey_bytes) throw new Error("pubkey-length");
  return { raw, b64: encodeB64Url(raw), privateKey: key.privateKey };
}

export function bytesOf(value: string, size: number): Uint8Array {
  const bytes = decodeB64Url(value);
  if (!bytes || bytes.length !== size) throw new Error("bytes");
  return bytes;
}

export function hexOf(value: string): Uint8Array {
  const bytes = decodeHex(value);
  if (!bytes) throw new Error("hex");
  return bytes;
}

export async function issueGrant(source = nextSource()): Promise<{ id: string; source_name: string }> {
  const source_name = await sourceObjectName(source);
  const granted = await env.GATE.getByName(source_name).tryAdmit(Date.now());
  if (!granted) throw new Error("grant");
  return { id: granted.id, source_name };
}

export async function openTicket(label: string, envelope = exampleEnvelope()): Promise<OpenedTicket> {
  const secret = exampleBytes(label);
  const issuerSecret = exampleBytes(`${label}i`);
  const name = encodeHex(await sha256(secret));
  const stub = env.TICKET.getByName(name);
  const grant = await issueGrant();
  const ticket = encodeB64Url(secret);
  const issuer = encodeB64Url(issuerSecret);
  const result = await stub.create({
    ticket,
    issuer_capability: issuer,
    envelope,
    grant_id: grant.id,
    grant_source: grant.source_name,
  });
  if (result.error || result.state !== "open" || result.expires_at === undefined) {
    throw new Error(result.error ?? "not-open");
  }
  return { name, stub, ticket, issuer, envelope, expiresAt: result.expires_at };
}

export async function openSession(label: string, who: Receiver): Promise<OpenedSession> {
  const secret = exampleBytes(label);
  const name = encodeHex(await sha256(secret));
  const stub = env.SESSION.getByName(name);
  const challenge = await stub.challenge({ sessionHash: name, purpose: "hello" });
  if (!challenge.nonce) throw new Error("hello-nonce");
  const signature = await signBytes(
    "hello",
    {
      origin: ORIGIN,
      server_nonce: bytesOf(challenge.nonce, protocol.nonce_bytes),
      receiver_pubkey: who.raw,
      pubkey: who.raw,
      session_hash: hexOf(name),
    },
    who.privateKey,
  );
  const hello = await stub.hello({
    sessionHash: name,
    pubkey: who.b64,
    nonce: challenge.nonce,
    signature: encodeB64Url(signature),
    origin: ORIGIN,
  });
  if (hello.error) throw new Error(hello.error);
  return { name, stub, capability: encodeB64Url(secret) };
}

export async function confirmDigest(input: {
  nonce: string;
  sessionHash: string;
  ticketHash: string;
  pubkey: Uint8Array;
}): Promise<string> {
  const digest = await requestDigest("confirm", {
    nonce: bytesOf(input.nonce, protocol.nonce_bytes),
    session_hash: hexOf(input.sessionHash),
    ticket_hash: hexOf(input.ticketHash),
    pubkey: input.pubkey,
  });
  return encodeB64Url(digest);
}

export async function signedRead(input: {
  who: Receiver;
  nonce: string;
  ticketHash: string;
  counter: number;
  origin?: string;
}): Promise<string> {
  const signature = await signBytes(
    "read",
    {
      origin: input.origin ?? ORIGIN,
      server_nonce: bytesOf(input.nonce, protocol.nonce_bytes),
      ticket_hash: hexOf(input.ticketHash),
      receiver_pubkey: input.who.raw,
      counter: input.counter,
    },
    input.who.privateKey,
  );
  return encodeB64Url(signature);
}

export async function signedAck(input: {
  who: Receiver;
  nonce: string;
  ticketHash: string;
  counter: number;
  envelopeHash: string;
  origin?: string;
}): Promise<string> {
  const signature = await signBytes(
    "ack",
    {
      origin: input.origin ?? ORIGIN,
      server_nonce: bytesOf(input.nonce, protocol.nonce_bytes),
      ticket_hash: hexOf(input.ticketHash),
      receiver_pubkey: input.who.raw,
      counter: input.counter,
      envelope_sha256: hexOf(input.envelopeHash),
    },
    input.who.privateKey,
  );
  return encodeB64Url(signature);
}

export async function signedRedeem(who: Receiver, seed: string, ticketHash: string): Promise<string> {
  const signature = await signBytes(
    "challenge",
    {
      origin: ORIGIN,
      server_nonce: bytesOf(seed, protocol.nonce_bytes),
      ticket_hash: hexOf(ticketHash),
      receiver_pubkey: who.raw,
    },
    who.privateKey,
  );
  return encodeB64Url(signature);
}

export async function bindTicket(
  label: string,
  who: Receiver,
  sessionHash: string,
): Promise<OpenedTicket> {
  const opened = await openTicket(label);
  const challenge = await opened.stub.challenge({ purpose: "confirm" });
  if (!challenge.nonce) throw new Error("confirm-nonce");
  const digest = await confirmDigest({
    nonce: challenge.nonce,
    sessionHash,
    ticketHash: opened.name,
    pubkey: who.raw,
  });
  const confirmed = await opened.stub.confirm({
    confirm: true,
    pubkey: who.b64,
    sessionHash,
    nonce: challenge.nonce,
    digest,
  });
  if (confirmed.error || confirmed.state !== "bound") throw new Error(confirmed.error ?? "not-bound");
  return opened;
}

export async function redeem(opened: OpenedTicket, who: Receiver): Promise<string> {
  const row = await dumpTicket(opened.name);
  if (!row.seed_nonce) throw new Error("seed");
  const signature = await signedRedeem(who, row.seed_nonce, opened.name);
  const result = await opened.stub.challenge({
    purpose: "op",
    pubkey: who.b64,
    signature,
    origin: ORIGIN,
  });
  if (!result.nonce || result.error) throw new Error(result.error ?? "redeem");
  return result.nonce;
}

export async function dumpTicket(name: string): Promise<TicketDump> {
  return runInDurableObject(env.TICKET.getByName(name), async (_instance, state) => {
    const rows = state.storage.sql
      .exec<{
        state: string;
        expires_at: number;
        envelope: string | null;
        op: number;
        bound_pubkey: string | null;
        seed_nonce: string | null;
        op_nonce: string | null;
        envelope_sha256: string | null;
      }>(
        `SELECT state, expires_at, envelope, op, bound_pubkey, seed_nonce, op_nonce, envelope_sha256
         FROM ticket WHERE id = 1`,
      )
      .toArray();
    const counts = state.storage.sql
      .exec<{ n: number }>("SELECT COUNT(*) AS n FROM pending_nonce")
      .toArray();
    const alarm = await state.storage.getAlarm();
    const row = rows[0];
    return {
      state: row?.state ?? null,
      expires_at: row ? Number(row.expires_at) : null,
      envelope: row?.envelope ?? null,
      op: row ? Number(row.op) : null,
      bound_pubkey: row?.bound_pubkey ?? null,
      seed_nonce: row?.seed_nonce ?? null,
      op_nonce: row?.op_nonce ?? null,
      envelope_sha256: row?.envelope_sha256 ?? null,
      nonces: counts[0] ? Number(counts[0].n) : 0,
      alarm: alarm ?? null,
    };
  });
}

export async function dumpSession(name: string): Promise<{
  columns: string[];
  text: string;
  hintSeed: string | null;
  pubkey: string | null;
  state: string | null;
  helloNonce: string | null;
  expiresAt: number | null;
}> {
  return runInDurableObject(env.SESSION.getByName(name), async (_instance, state) => {
    const columns = state.storage.sql
      .exec<{ name: string }>("PRAGMA table_info(session)")
      .toArray()
      .map((column) => column.name);
    const rows = state.storage.sql
      .exec<{
        pubkey: string | null;
        state: string | null;
        hint_seed_nonce: string | null;
        hello_nonce: string | null;
        expires_at: number | null;
      }>("SELECT pubkey, state, hint_seed_nonce, hello_nonce, expires_at FROM session WHERE id = 1")
      .toArray();
    const all = state.storage.sql.exec("SELECT * FROM session WHERE id = 1").toArray();
    const row = rows[0];
    return {
      columns,
      text: JSON.stringify({ columns, all }),
      hintSeed: row?.hint_seed_nonce ?? null,
      pubkey: row?.pubkey ?? null,
      state: row?.state ?? null,
      helloNonce: row?.hello_nonce ?? null,
      expiresAt: row?.expires_at === null || row?.expires_at === undefined ? null : Number(row.expires_at),
    };
  });
}

export async function setTicketExpiry(name: string, expiresAt: number): Promise<void> {
  await runInDurableObject(env.TICKET.getByName(name), async (_instance, state) => {
    state.storage.sql.exec("UPDATE ticket SET expires_at = ? WHERE id = 1", expiresAt);
  });
}

export async function post(
  path: string,
  body: unknown,
  source = nextSource(),
): Promise<{ status: number; text: string; json: Record<string, unknown>; headers: Headers }> {
  const response = await SELF.fetch(`${ORIGIN}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "CF-Connecting-IP": source,
    },
    body: JSON.stringify(body),
  });
  const text = await response.text();
  let json: Record<string, unknown> = {};
  try {
    json = JSON.parse(text) as Record<string, unknown>;
  } catch {
    json = {};
  }
  return { status: response.status, text, json, headers: response.headers };
}
