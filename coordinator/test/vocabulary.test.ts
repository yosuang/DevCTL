import { expect, it } from "vitest";
import bindSource from "../src/bind.ts?raw";
import envelopeSource from "../src/envelope.ts?raw";
import gateSource from "../src/gate.ts?raw";
import sessionSource from "../src/session.ts?raw";
import { requestDigest, signedMessage } from "../src/sign";
import ticketSource from "../src/ticket.ts?raw";
import { protocol } from "../src/protocol";

const encoder = new TextEncoder();

function join(parts: Uint8Array[]): Uint8Array {
  let length = 0;
  for (const part of parts) length += part.byteLength;
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.byteLength;
  }
  return out;
}

async function digest(parts: Uint8Array[]): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", join(parts)));
}

it("publishes one vocabulary for states, errors, envelopes, and signature order", async () => {
  expect(protocol.version).toBe(1);
  expect(protocol.states).toEqual(["open", "bound", "consumed", "expired", "cancelled"]);
  expect(protocol.terminal_states).toEqual(["consumed", "expired", "cancelled"]);
  expect(protocol.hint_states).toEqual(["bound", "expired", "cancelled"]);
  expect(protocol.errors.server).toEqual([
    "bad_request",
    "confirm_required",
    "unauthorized",
    "forbidden",
    "ticket_not_found",
    "session_not_found",
    "ticket_bound",
    "ticket_not_bound",
    "consumed",
    "expired",
    "cancelled",
    "payload_gone",
    "bound_notify_pending",
    "too_large",
    "unsupported_version",
    "rate_limited",
    "conflict",
  ]);
  expect(protocol.envelope).toMatchObject({
    name: "devctl-pair-v1",
    kdf: "argon2id",
    kdf_version: "0x13",
    m: 65536,
    t: 3,
    p: 4,
    salt_bytes: 16,
    key_bytes: 32,
    aead: "aes-256-gcm",
    nonce_bytes: 12,
    tag_bytes: 16,
    max_bytes: 65536,
  });
  expect(protocol.limits).toMatchObject({
    source_admits_per_window: 3,
    window_ms: 300000,
    shard_count: 16,
    shard_admits_per_window: 4,
    grant_ttl_ms: 60000,
    ticket_ttl_ms: 300000,
    envelope_max_bytes: 65536,
    request_max_bytes: 73728,
  });
  expect(protocol.signatures.read).toMatchObject({
    scope: "devctl-pair/read/v1",
    method: "POST",
    path: "/v1/tickets/read",
  });
  expect(protocol.signatures.ack.path).toBe("/v1/tickets/ack");
  expect(protocol.signatures.wait.path).toBe("/v1/sessions/wait");
  expect(protocol.signatures.challenge.path).toBe("/v1/tickets/challenge");
  expect(protocol.signatures.hello.scope).toBe("devctl-pair/hello/v1");
  expect(protocol.signatures.confirm.scope).toBe("devctl-pair/confirm/v1");
  expect(protocol.signatures.cancel.scope).toBe("devctl-pair/cancel/v1");
  expect(protocol.routes.ticket_read).toBe(protocol.signatures.read.path);
  expect(protocol.routes.ticket_ack).toBe(protocol.signatures.ack.path);
  expect(protocol.routes.session_wait).toBe(protocol.signatures.wait.path);
  expect(protocol.routes.ticket_challenge).toBe(protocol.signatures.challenge.path);

  const zero = new Uint8Array([1 - 1]);
  const counter = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 7]);
  const ticketHash = new Uint8Array(32).fill(0x11);
  const pubkey = new Uint8Array(32).fill(0x33);
  const nonce = new Uint8Array(32).fill(0x22);
  const origin = encoder.encode("http://127.0.0.1:8787");
  const readDigest = await digest([
    encoder.encode("POST"),
    zero,
    encoder.encode("/v1/tickets/read"),
    zero,
    origin,
    zero,
    ticketHash,
    counter,
  ]);
  const readMessage = join([
    encoder.encode("devctl-pair/read/v1"),
    zero,
    nonce,
    ticketHash,
    pubkey,
    counter,
    readDigest,
  ]);
  expect(
    await signedMessage("read", {
      origin: "http://127.0.0.1:8787",
      server_nonce: nonce,
      ticket_hash: ticketHash,
      receiver_pubkey: pubkey,
      counter: 7,
    }),
  ).toEqual(readMessage);

  const sessionHash = new Uint8Array(32).fill(0x44);
  const confirmDigest = await digest([
    encoder.encode("devctl-pair/confirm/v1"),
    zero,
    nonce,
    sessionHash,
    ticketHash,
    pubkey,
    new Uint8Array([1]),
  ]);
  expect(
    await requestDigest("confirm", {
      nonce,
      session_hash: sessionHash,
      ticket_hash: ticketHash,
      pubkey,
    }),
  ).toEqual(confirmDigest);
});

it("keeps storage commits local to the durable object", () => {
  for (const source of [ticketSource, sessionSource, gateSource, bindSource]) {
    expect(source).not.toContain("deleteAll");
    expect(source).not.toContain("await fetch(");
    expect(source).not.toContain("globalThis.fetch");
  }
  expect(ticketSource).not.toContain("fetch(");
  expect(gateSource).not.toContain("fetch(");
  expect(sessionSource).not.toContain("TICKET");
  expect(ticketSource).not.toContain("argon2id");
  expect(envelopeSource).not.toContain("argon2id");
  expect(envelopeSource).not.toContain("deriveBits");
  const confirmBody = ticketSource.slice(
    ticketSource.indexOf("#commitConfirm(pubkey:"),
    ticketSource.indexOf("#commitRead(pubkey:"),
  );
  expect(confirmBody).not.toContain("await");
  expect(confirmBody).not.toContain("fetch");
  expect(bindSource.indexOf("session.notify")).toBeGreaterThan(bindSource.indexOf("ticket.confirm"));
});
