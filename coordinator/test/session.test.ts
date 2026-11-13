import { env, runInDurableObject } from "cloudflare:test";
import { expect, it } from "vitest";
import { finishConfirm } from "../src/bind";
import { encodeB64Url, encodeHex, sha256 } from "../src/bytes";
import { protocol } from "../src/protocol";
import { signBytes } from "../src/sign";
import {
  CIPHERTEXT,
  ORIGIN,
  PASSPHRASE,
  SHARE_URI,
  bindTicket,
  bytesOf,
  confirmDigest,
  dumpSession,
  dumpTicket,
  exampleBytes,
  hexOf,
  openSession,
  openTicket,
  receiver,
} from "./support";

it("session storage has no envelope", async () => {
  const who = await receiver();
  const session = await openSession("stored", who);
  const opened = await bindTicket("storet", who, session.name);
  const hint = (await opened.stub.confirm({ confirm: false })).hint;
  expect(hint).toBeUndefined();
  const challenge = await opened.stub.challenge({ purpose: "confirm" });
  const confirmed = await opened.stub.confirm({
    confirm: true,
    pubkey: who.b64,
    sessionHash: session.name,
    nonce: challenge.nonce,
    digest: await confirmDigest({
      nonce: challenge.nonce ?? "",
      sessionHash: session.name,
      ticketHash: opened.name,
      pubkey: who.raw,
    }),
  });
  expect(confirmed.hint?.state).toBe("bound");
  expect(await session.stub.notify(confirmed.hint!)).toBe(true);
  const stored = await dumpSession(session.name);
  expect(stored.columns).not.toContain("envelope");
  expect(stored.columns).not.toContain("ct");
  expect(stored.hintSeed).toBe(confirmed.hint?.seed_nonce);
  expect(stored.pubkey).toBe(who.b64);
  expect(stored.text).not.toContain(CIPHERTEXT);
  expect(stored.text).not.toContain(PASSPHRASE);
  expect(stored.text).not.toContain(SHARE_URI);
  expect(stored.text).not.toContain("argon2id");
  expect(stored.text).not.toContain("example-auth-not-a-secret");
  const ticket = await dumpTicket(opened.name);
  expect(ticket.envelope).toBe(opened.envelope);
  expect(ticket.state).toBe("bound");
});

it("failed notification does not roll back a bind", async () => {
  const who = await receiver();
  const session = await openSession("ntfy", who);
  await runInDurableObject(session.stub, async (_instance, state) => {
    state.storage.sql.exec("UPDATE session SET expires_at = 1 WHERE id = 1");
  });
  const opened = await openTicket("ntfyt");
  const beforeExpiry = opened.expiresAt;
  const challenge = await opened.stub.challenge({ purpose: "confirm" });
  const result = await finishConfirm(env, {
    ticket: opened.ticket,
    sessionCapability: session.capability,
    confirm: true,
    nonce: challenge.nonce ?? "",
    digest: await confirmDigest({
      nonce: challenge.nonce ?? "",
      sessionHash: session.name,
      ticketHash: opened.name,
      pubkey: who.raw,
    }),
  });
  expect(result.error).toBe("bound_notify_pending");
  expect(result.state).toBe("bound");
  expect(Object.keys(result).sort()).toEqual(["error", "expires_at", "fingerprint", "state", "v"].sort());
  const ticket = await dumpTicket(opened.name);
  expect(ticket.state).toBe("bound");
  expect(ticket.envelope).toBe(opened.envelope);
  expect(ticket.expires_at).toBe(beforeExpiry);
  expect(ticket.seed_nonce).toBeTypeOf("string");
  expect(JSON.stringify(result)).not.toContain(ticket.seed_nonce ?? "");
  expect((await dumpSession(session.name)).hintSeed).toBeNull();

  await runInDurableObject(session.stub, async (_instance, state) => {
    state.storage.sql.exec("UPDATE session SET expires_at = ? WHERE id = 1", Date.now() + 60_000);
  });
  const retry = await opened.stub.challenge({ purpose: "confirm" });
  const second = await finishConfirm(env, {
    ticket: opened.ticket,
    sessionCapability: session.capability,
    confirm: true,
    nonce: retry.nonce ?? "",
    digest: await confirmDigest({
      nonce: retry.nonce ?? "",
      sessionHash: session.name,
      ticketHash: opened.name,
      pubkey: who.raw,
    }),
  });
  expect(second.error).toBeUndefined();
  expect(second.state).toBe("bound");
  const after = await dumpTicket(opened.name);
  expect(after.envelope).toBe(opened.envelope);
  expect(after.expires_at).toBe(beforeExpiry);
  expect(after.seed_nonce).toBe(ticket.seed_nonce);
  expect(after.op).toBe(0);
  expect((await dumpSession(session.name)).hintSeed).toBe(ticket.seed_nonce);
});

it("hello rejects a different public key and keeps the nonce", async () => {
  const owner = await receiver();
  const session = await openSession("hellok", owner);
  const before = await dumpSession(session.name);
  const challenge = await session.stub.challenge({ sessionHash: session.name, purpose: "hello" });
  const other = await receiver();
  const deniedSignature = await signBytes(
    "hello",
    {
      origin: ORIGIN,
      server_nonce: bytesOf(challenge.nonce ?? "", protocol.nonce_bytes),
      receiver_pubkey: other.raw,
      pubkey: other.raw,
      session_hash: hexOf(session.name),
    },
    other.privateKey,
  );
  const denied = await session.stub.hello({
    sessionHash: session.name,
    pubkey: other.b64,
    nonce: challenge.nonce ?? "",
    signature: encodeB64Url(deniedSignature),
    origin: ORIGIN,
  });
  expect(denied.error).toBe("forbidden");
  expect((await dumpSession(session.name)).helloNonce).toBe(challenge.nonce);
  expect((await dumpSession(session.name)).pubkey).toBe(owner.b64);
  expect((await dumpSession(session.name)).expiresAt).toBe(before.expiresAt);
  const allowedSignature = await signBytes(
    "hello",
    {
      origin: ORIGIN,
      server_nonce: bytesOf(challenge.nonce ?? "", protocol.nonce_bytes),
      receiver_pubkey: owner.raw,
      pubkey: owner.raw,
      session_hash: hexOf(session.name),
    },
    owner.privateKey,
  );
  const allowed = await session.stub.hello({
    sessionHash: session.name,
    pubkey: owner.b64,
    nonce: challenge.nonce ?? "",
    signature: encodeB64Url(allowedSignature),
    origin: ORIGIN,
  });
  expect(allowed.error).toBeUndefined();
  expect((await dumpSession(session.name)).helloNonce).toBeNull();
  expect((await dumpSession(session.name)).expiresAt).toBe(before.expiresAt);
});

it("accepts a hibernating socket and pushes a hint without ciphertext", async () => {
  const who = await receiver();
  const secret = exampleBytes("socket");
  const name = encodeHex(await sha256(secret));
  const stub = env.SESSION.getByName(name);
  const response = await stub.fetch(`${ORIGIN}/v1/sessions/socket`, {
    headers: {
      Upgrade: "websocket",
      [protocol.session_header]: name,
    },
  });
  expect(response.status).toBe(101);
  const socket = response.webSocket;
  expect(socket).toBeTruthy();
  if (!socket) throw new Error("socket");
  const incoming = new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("challenge-timeout")), 2000);
    socket.addEventListener("message", (event) => {
      clearTimeout(timer);
      resolve(String(event.data));
    });
  });
  socket.accept();
  const challengeText = await incoming;
  const challenge = JSON.parse(challengeText) as { v: number; type: string; nonce: string };
  expect(challenge).toEqual({ v: 1, type: "challenge", nonce: challenge.nonce });
  expect(challengeText).not.toContain(CIPHERTEXT);
  await runInDurableObject(stub, async (_instance, state) => {
    expect(state.getWebSockets().length).toBe(1);
    expect(state.getWebSocketAutoResponse()).not.toBeNull();
  });
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
  const helloText = new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("hello-timeout")), 2000);
    socket.addEventListener("message", (event) => {
      clearTimeout(timer);
      resolve(String(event.data));
    });
  });
  socket.send(JSON.stringify({ v: 1, type: "hello_proof", pubkey: who.b64, signature: encodeB64Url(signature) }));
  const hello = JSON.parse(await helloText) as { v: number; type: string; fingerprint: string };
  expect(hello.type).toBe("hello");
  expect(hello.v).toBe(1);
  const opened = await openTicket("sockt");
  const confirmNonce = (await opened.stub.challenge({ purpose: "confirm" })).nonce ?? "";
  const hintText = new Promise<string>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("hint-timeout")), 2000);
    socket.addEventListener("message", (event) => {
      clearTimeout(timer);
      resolve(String(event.data));
    });
  });
  const confirmed = await opened.stub.confirm({
    confirm: true,
    pubkey: who.b64,
    sessionHash: name,
    nonce: confirmNonce,
    digest: await confirmDigest({
      nonce: confirmNonce,
      sessionHash: name,
      ticketHash: opened.name,
      pubkey: who.raw,
    }),
  });
  expect(await stub.notify(confirmed.hint!)).toBe(true);
  const hint = JSON.parse(await hintText) as Record<string, unknown>;
  expect(Object.keys(hint).sort()).toEqual([...protocol.hint_fields].sort());
  expect(JSON.stringify(hint)).not.toContain(CIPHERTEXT);
  expect(JSON.stringify(hint)).not.toContain(PASSPHRASE);
  expect(JSON.stringify(hint)).not.toContain(SHARE_URI);
  expect(JSON.stringify(hint)).not.toContain("argon2id");
  const stored = await dumpSession(name);
  expect(stored.columns).not.toContain("envelope");
  expect(stored.text).not.toContain(CIPHERTEXT);
});
