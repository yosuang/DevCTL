import { env, runDurableObjectAlarm } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { encodeB64Url, encodeHex, fingerprint, sha256, utf8 } from "../src/bytes";
import { protocol } from "../src/protocol";
import { finishConfirm } from "../src/bind";
import {
  CIPHERTEXT,
  ORIGIN,
  PASSPHRASE,
  bindTicket,
  bytesOf,
  confirmDigest,
  dumpTicket,
  exampleBytes,
  exampleEnvelope,
  hexOf,
  issueGrant,
  openTicket,
  receiver,
  redeem,
  setTicketExpiry,
  signedAck,
  signedRead,
  type OpenedTicket,
  type Receiver,
} from "./support";

async function sessionHash(label: string): Promise<string> {
  return encodeHex(await sha256(exampleBytes(label)));
}

async function bound(label: string): Promise<{ who: Receiver; opened: OpenedTicket; session: string }> {
  const who = await receiver();
  const session = await sessionHash(`${label}s`);
  const opened = await bindTicket(label, who, session);
  return { who, opened, session };
}

describe("ticket state", () => {
  it("uses 32-byte example fixtures", () => {
    const ticket = exampleBytes("ticket");
    expect(ticket.length).toBe(32);
    const text = new TextDecoder().decode(ticket);
    expect(text).toContain("example-");
    expect(text).toContain("not-a-secret");
    expect(utf8(CIPHERTEXT).length).toBe(31);
    expect(PASSPHRASE).toBe("example-passphrase-not-a-secret");
  });

  it("create without a grant writes nothing", async () => {
    const secret = exampleBytes("nogrant");
    const name = encodeHex(await sha256(secret));
    const stub = env.TICKET.getByName(name);
    const result = await stub.create({
      ticket: encodeB64Url(secret),
      issuer_capability: encodeB64Url(exampleBytes("nogranti")),
      envelope: exampleEnvelope(),
    });
    expect(result).toEqual({ v: 1, error: "unauthorized" });
    const row = await dumpTicket(name);
    expect(row.state).toBeNull();
    expect(row.envelope).toBeNull();
    expect(row.alarm).toBeNull();
  });

  it("an unknown envelope writes nothing and does not derive a key", async () => {
    const secret = exampleBytes("badenv");
    const name = encodeHex(await sha256(secret));
    const parsed = JSON.parse(exampleEnvelope()) as Record<string, unknown>;
    parsed.extra = PASSPHRASE;
    const result = await env.TICKET.getByName(name).create({
      ticket: encodeB64Url(secret),
      issuer_capability: encodeB64Url(exampleBytes("badenvi")),
      envelope: JSON.stringify(parsed),
    });
    expect(result.error).toBe("unsupported_version");
    const row = await dumpTicket(name);
    expect(row.state).toBeNull();
    expect(row.alarm).toBeNull();
  });

  it("preview has no side effects and does not return ciphertext", async () => {
    const opened = await openTicket("preview");
    const before = await dumpTicket(opened.name);
    expect(before.alarm).toBe(before.expires_at);
    expect(before.envelope).toBe(opened.envelope);
    const preview = await opened.stub.preview();
    expect(preview).toEqual({ v: 1, state: "open", expires_at: before.expires_at });
    expect(JSON.stringify(preview)).not.toContain(CIPHERTEXT);
    expect(JSON.stringify(preview)).not.toContain("argon2id");
    expect(await dumpTicket(opened.name)).toEqual(before);
    await setTicketExpiry(opened.name, 1);
    const due = await opened.stub.preview();
    expect(due.state).toBe("open");
    expect(due.expires_at).toBe(1);
    const after = await dumpTicket(opened.name);
    expect(after.state).toBe("open");
    expect(after.envelope).toBe(opened.envelope);
    expect(after.alarm).toBe(before.alarm);
  });

  it("confirm must be true", async () => {
    const who = await receiver();
    const opened = await openTicket("confalse");
    const session = await sessionHash("confalses");
    const before = await dumpTicket(opened.name);
    const refused = await opened.stub.confirm({ confirm: false });
    expect(refused.error).toBe("confirm_required");
    expect(refused.state).toBe("open");
    expect(await dumpTicket(opened.name)).toEqual(before);
    const challenge = await opened.stub.challenge({ purpose: "confirm" });
    expect(challenge.nonce).toBeTypeOf("string");
    const still = await opened.stub.confirm({ confirm: false });
    expect(still.error).toBe("confirm_required");
    const digest = await confirmDigest({
      nonce: challenge.nonce ?? "",
      sessionHash: session,
      ticketHash: opened.name,
      pubkey: who.raw,
    });
    const accepted = await opened.stub.confirm({
      confirm: true,
      pubkey: who.b64,
      sessionHash: session,
      nonce: challenge.nonce,
      digest,
    });
    expect(accepted.state).toBe("bound");
    expect(accepted.error).toBeUndefined();
    expect(accepted.fingerprint).toBe(await fingerprint(who.raw));
    const row = await dumpTicket(opened.name);
    expect(row.state).toBe("bound");
    expect(row.envelope).toBe(opened.envelope);
    expect(row.expires_at).toBe(before.expires_at);
  });

  it("concurrent confirms have one winner", async () => {
    const opened = await openTicket("race");
    const first = await receiver();
    const second = await receiver();
    const session = await sessionHash("races");
    const left = await opened.stub.challenge({ purpose: "confirm" });
    const right = await opened.stub.challenge({ purpose: "confirm" });
    const [one, two] = await Promise.all([
      opened.stub.confirm({
        confirm: true,
        pubkey: first.b64,
        sessionHash: session,
        nonce: left.nonce,
        digest: await confirmDigest({
          nonce: left.nonce ?? "",
          sessionHash: session,
          ticketHash: opened.name,
          pubkey: first.raw,
        }),
      }),
      opened.stub.confirm({
        confirm: true,
        pubkey: second.b64,
        sessionHash: session,
        nonce: right.nonce,
        digest: await confirmDigest({
          nonce: right.nonce ?? "",
          sessionHash: session,
          ticketHash: opened.name,
          pubkey: second.raw,
        }),
      }),
    ]);
    const results = [one, two];
    expect(results.filter((result) => result.state === "bound" && !result.error)).toHaveLength(1);
    expect(results.filter((result) => result.error === "ticket_bound")).toHaveLength(1);
    const row = await dumpTicket(opened.name);
    expect(row.state).toBe("bound");
    expect([first.b64, second.b64]).toContain(row.bound_pubkey);
    expect(row.envelope).toBe(opened.envelope);
    expect(row.op).toBe(0);
  });

  it("the same key can confirm again without changing ciphertext or expiry", async () => {
    const { who, opened, session } = await bound("idemp");
    const before = await dumpTicket(opened.name);
    const challenge = await opened.stub.challenge({ purpose: "confirm" });
    const again = await opened.stub.confirm({
      confirm: true,
      pubkey: who.b64,
      sessionHash: session,
      nonce: challenge.nonce,
      digest: await confirmDigest({
        nonce: challenge.nonce ?? "",
        sessionHash: session,
        ticketHash: opened.name,
        pubkey: who.raw,
      }),
    });
    expect(again).toMatchObject({ v: 1, state: "bound", expires_at: before.expires_at, fingerprint: before.bound_pubkey && (await fingerprint(who.raw)) });
    expect(again.error).toBeUndefined();
    const after = await dumpTicket(opened.name);
    expect(after.state).toBe("bound");
    expect(after.envelope).toBe(before.envelope);
    expect(after.expires_at).toBe(before.expires_at);
    expect(after.op).toBe(before.op);
    expect(after.bound_pubkey).toBe(who.b64);
    expect(after.seed_nonce).toBe(before.seed_nonce);
    const replay = await opened.stub.confirm({
      confirm: true,
      pubkey: who.b64,
      sessionHash: session,
      nonce: challenge.nonce,
      digest: await confirmDigest({
        nonce: challenge.nonce ?? "",
        sessionHash: session,
        ticketHash: opened.name,
        pubkey: who.raw,
      }),
    });
    expect(replay.error).toBe("unauthorized");
    expect((await dumpTicket(opened.name)).op).toBe(before.op);
    expect((await dumpTicket(opened.name)).state).toBe("bound");
  });

  it("another key cannot read or ack", async () => {
    const { who, opened } = await bound("other");
    const nonce = await redeem(opened, who);
    const stranger = await receiver();
    const before = await dumpTicket(opened.name);
    const read = await opened.stub.read({
      pubkey: stranger.b64,
      nonce,
      counter: 0,
      signature: await signedRead({ who: stranger, nonce, ticketHash: opened.name, counter: 0 }),
      origin: ORIGIN,
    });
    expect(read.error).toBe("forbidden");
    expect(read.envelope).toBeUndefined();
    expect(await dumpTicket(opened.name)).toEqual(before);
    const ack = await opened.stub.ack({
      pubkey: stranger.b64,
      nonce,
      counter: 0,
      signature: await signedAck({
        who: stranger,
        nonce,
        ticketHash: opened.name,
        counter: 0,
        envelopeHash: before.envelope_sha256 ?? "",
      }),
      origin: ORIGIN,
    });
    expect(ack.error).toBe("forbidden");
    expect(ack.envelope).toBeUndefined();
    expect(await dumpTicket(opened.name)).toEqual(before);
    const owner = await opened.stub.read({
      pubkey: who.b64,
      nonce,
      counter: 0,
      signature: await signedRead({ who, nonce, ticketHash: opened.name, counter: 0 }),
      origin: ORIGIN,
    });
    expect(owner.envelope).toBe(opened.envelope);
    expect(owner.state).toBe("bound");
  });

  it("a bad signature does not burn the nonce", async () => {
    const { who, opened } = await bound("badsig");
    const nonce = await redeem(opened, who);
    const signature = await signedRead({ who, nonce, ticketHash: opened.name, counter: 0 });
    const raw = bytesOf(signature, 64);
    raw[0] ^= 0xff;
    const denied = await opened.stub.read({
      pubkey: who.b64,
      nonce,
      counter: 0,
      signature: encodeB64Url(raw),
      origin: ORIGIN,
    });
    expect(denied.error).toBe("unauthorized");
    expect((await dumpTicket(opened.name)).op_nonce).toBe(nonce);
    expect((await dumpTicket(opened.name)).op).toBe(0);
    const allowed = await opened.stub.read({
      pubkey: who.b64,
      nonce,
      counter: 0,
      signature,
      origin: ORIGIN,
    });
    expect(allowed.envelope).toBe(opened.envelope);
  });

  it("a replayed read does not advance state or return ciphertext", async () => {
    const { who, opened } = await bound("replayr");
    const nonce = await redeem(opened, who);
    const signature = await signedRead({ who, nonce, ticketHash: opened.name, counter: 0 });
    const first = await opened.stub.read({
      pubkey: who.b64,
      nonce,
      counter: 0,
      signature,
      origin: ORIGIN,
    });
    expect(first.envelope).toBe(opened.envelope);
    const replay = await opened.stub.read({
      pubkey: who.b64,
      nonce,
      counter: 0,
      signature,
      origin: ORIGIN,
    });
    expect(replay.error).toBe("unauthorized");
    expect(replay.envelope).toBeUndefined();
    const row = await dumpTicket(opened.name);
    expect(row.state).toBe("bound");
    expect(row.op).toBe(1);
    expect(row.envelope).toBe(opened.envelope);
  });

  it("two reads while bound both return ciphertext", async () => {
    const { who, opened } = await bound("tworead");
    const firstNonce = await redeem(opened, who);
    const first = await opened.stub.read({
      pubkey: who.b64,
      nonce: firstNonce,
      counter: 0,
      signature: await signedRead({ who, nonce: firstNonce, ticketHash: opened.name, counter: 0 }),
      origin: ORIGIN,
    });
    const secondNonce = (await opened.stub.challenge({ purpose: "op" })).nonce ?? "";
    const second = await opened.stub.read({
      pubkey: who.b64,
      nonce: secondNonce,
      counter: 1,
      signature: await signedRead({ who, nonce: secondNonce, ticketHash: opened.name, counter: 1 }),
      origin: ORIGIN,
    });
    expect(first.envelope).toBe(opened.envelope);
    expect(second.envelope).toBe(opened.envelope);
    const row = await dumpTicket(opened.name);
    expect(row.state).toBe("bound");
    expect(row.op).toBe(2);
    expect(row.envelope).toBe(opened.envelope);
  });

  it("read does not expire a due ticket", async () => {
    const { who, opened } = await bound("dueread");
    await setTicketExpiry(opened.name, 1);
    const nonce = await redeem(opened, who);
    const result = await opened.stub.read({
      pubkey: who.b64,
      nonce,
      counter: 0,
      signature: await signedRead({ who, nonce, ticketHash: opened.name, counter: 0 }),
      origin: ORIGIN,
    });
    expect(result.envelope).toBe(opened.envelope);
    expect(result.state).toBe("bound");
    const row = await dumpTicket(opened.name);
    expect(row.state).toBe("bound");
    expect(row.envelope).toBe(opened.envelope);
  });

  it("ack deletes ciphertext and a second ack stays consumed", async () => {
    const { who, opened } = await bound("ackdel");
    const before = await dumpTicket(opened.name);
    const nonce = await redeem(opened, who);
    const acked = await opened.stub.ack({
      pubkey: who.b64,
      nonce,
      counter: 0,
      signature: await signedAck({
        who,
        nonce,
        ticketHash: opened.name,
        counter: 0,
        envelopeHash: before.envelope_sha256 ?? "",
      }),
      origin: ORIGIN,
    });
    expect(acked).toEqual({ v: 1, state: "consumed" });
    const consumed = await dumpTicket(opened.name);
    expect(consumed.state).toBe("consumed");
    expect(consumed.envelope).toBeNull();
    expect(consumed.op).toBe(1);
    expect(consumed.envelope_sha256).toBe(before.envelope_sha256);
    const next = (await opened.stub.challenge({ purpose: "op" })).nonce ?? "";
    const second = await opened.stub.ack({
      pubkey: who.b64,
      nonce: next,
      counter: 1,
      signature: await signedAck({
        who,
        nonce: next,
        ticketHash: opened.name,
        counter: 1,
        envelopeHash: before.envelope_sha256 ?? "",
      }),
      origin: ORIGIN,
    });
    expect(second).toEqual({ v: 1, state: "consumed" });
    const after = await dumpTicket(opened.name);
    expect(after.state).toBe("consumed");
    expect(after.envelope).toBeNull();
    expect(after.op).toBe(1);
  });

  it("alarm then ack leaves an empty tombstone", async () => {
    const { who, opened } = await bound("alack");
    const before = await dumpTicket(opened.name);
    const nonce = await redeem(opened, who);
    await setTicketExpiry(opened.name, 1);
    expect(await runDurableObjectAlarm(opened.stub)).toBe(true);
    const expired = await dumpTicket(opened.name);
    expect(expired.state).toBe("expired");
    expect(expired.envelope).toBeNull();
    expect(expired.bound_pubkey).toBe(who.b64);
    const ack = await opened.stub.ack({
      pubkey: who.b64,
      nonce,
      counter: 0,
      signature: await signedAck({
        who,
        nonce,
        ticketHash: opened.name,
        counter: 0,
        envelopeHash: before.envelope_sha256 ?? "",
      }),
      origin: ORIGIN,
    });
    expect(ack.envelope).toBeUndefined();
    const after = await dumpTicket(opened.name);
    expect(after.state).toBe("expired");
    expect(after.envelope).toBeNull();
    expect(after.state).not.toBe("open");
  });

  it("ack then alarm does not restore ciphertext", async () => {
    const { who, opened } = await bound("ackal");
    const before = await dumpTicket(opened.name);
    expect(before.expires_at).toBeGreaterThan(Date.now());
    const nonce = await redeem(opened, who);
    const acked = await opened.stub.ack({
      pubkey: who.b64,
      nonce,
      counter: 0,
      signature: await signedAck({
        who,
        nonce,
        ticketHash: opened.name,
        counter: 0,
        envelopeHash: before.envelope_sha256 ?? "",
      }),
      origin: ORIGIN,
    });
    expect(acked.state).toBe("consumed");
    expect(await runDurableObjectAlarm(opened.stub)).toBe(true);
    const after = await dumpTicket(opened.name);
    expect(after.state).toBe("consumed");
    expect(after.envelope).toBeNull();
    expect(after.expires_at).toBe(before.expires_at);
  });

  it("an open alarm leaves a tombstone that cannot be reopened", async () => {
    const opened = await openTicket("reopen");
    await setTicketExpiry(opened.name, 1);
    expect(await runDurableObjectAlarm(opened.stub)).toBe(true);
    const expired = await dumpTicket(opened.name);
    expect(expired.state).toBe("expired");
    expect(expired.envelope).toBeNull();
    const grant = await issueGrant();
    const again = await opened.stub.create({
      ticket: opened.ticket,
      issuer_capability: opened.issuer,
      envelope: opened.envelope,
      grant_id: grant.id,
      grant_source: grant.source_name,
    });
    expect(again.error).toBe("expired");
    expect(again.state).toBe("expired");
    const after = await dumpTicket(opened.name);
    expect(after.state).toBe("expired");
    expect(after.envelope).toBeNull();
  });

  it("redeem does not advance the counter", async () => {
    const { who, opened } = await bound("redeem");
    const denied = await opened.stub.challenge({ purpose: "op" });
    expect(denied.error).toBe("unauthorized");
    expect((await dumpTicket(opened.name)).op).toBe(0);
    const nonce = await redeem(opened, who);
    const row = await dumpTicket(opened.name);
    expect(row.op).toBe(0);
    expect(row.seed_nonce).toBeNull();
    expect(row.op_nonce).toBe(nonce);
    expect(row.envelope).toBe(opened.envelope);
    expect(row.state).toBe("bound");
  });

  it("the wrong issuer cannot cancel", async () => {
    const opened = await openTicket("issuer");
    const challenge = await opened.stub.challenge({ purpose: "cancel" });
    const before = await dumpTicket(opened.name);
    const wrong = exampleBytes("issuerx");
    const { requestDigest } = await import("../src/sign");
    const digest = encodeB64Url(
      await requestDigest("cancel", {
        nonce: bytesOf(challenge.nonce ?? "", protocol.nonce_bytes),
        ticket_hash: hexOf(opened.name),
        issuer_hash: await sha256(wrong),
      }),
    );
    const result = await opened.stub.cancel({
      issuer_capability: encodeB64Url(wrong),
      nonce: challenge.nonce ?? "",
      digest,
    });
    expect(result.error).toBe("unauthorized");
    expect(await dumpTicket(opened.name)).toEqual(before);
  });

  it("cancel deletes ciphertext and a later cancel stays cancelled", async () => {
    const opened = await openTicket("cancel");
    const challenge = await opened.stub.challenge({ purpose: "cancel" });
    const issuer = exampleBytes("canceli");
    const { requestDigest } = await import("../src/sign");
    const digest = encodeB64Url(
      await requestDigest("cancel", {
        nonce: bytesOf(challenge.nonce ?? "", protocol.nonce_bytes),
        ticket_hash: hexOf(opened.name),
        issuer_hash: await sha256(issuer),
      }),
    );
    const result = await opened.stub.cancel({
      issuer_capability: encodeB64Url(issuer),
      nonce: challenge.nonce ?? "",
      digest,
    });
    expect(result.state).toBe("cancelled");
    const row = await dumpTicket(opened.name);
    expect(row.state).toBe("cancelled");
    expect(row.envelope).toBeNull();
    const again = await opened.stub.challenge({ purpose: "cancel" });
    const second = await opened.stub.cancel({
      issuer_capability: encodeB64Url(issuer),
      nonce: again.nonce ?? "",
      digest: encodeB64Url(
        await requestDigest("cancel", {
          nonce: bytesOf(again.nonce ?? "", protocol.nonce_bytes),
          ticket_hash: hexOf(opened.name),
          issuer_hash: await sha256(issuer),
        }),
      ),
    });
    expect(second.error).toBe("cancelled");
    expect((await dumpTicket(opened.name)).state).toBe("cancelled");
    expect((await dumpTicket(opened.name)).envelope).toBeNull();
  });

  it("cancel of a consumed ticket stays consumed", async () => {
    const { who, opened } = await bound("ackcan");
    const hash = (await dumpTicket(opened.name)).envelope_sha256 ?? "";
    const nonce = await redeem(opened, who);
    await opened.stub.ack({
      pubkey: who.b64,
      nonce,
      counter: 0,
      signature: await signedAck({ who, nonce, ticketHash: opened.name, counter: 0, envelopeHash: hash }),
      origin: ORIGIN,
    });
    const challenge = await opened.stub.challenge({ purpose: "cancel" });
    const issuer = exampleBytes("ackcani");
    const { requestDigest } = await import("../src/sign");
    const result = await opened.stub.cancel({
      issuer_capability: encodeB64Url(issuer),
      nonce: challenge.nonce ?? "",
      digest: encodeB64Url(
        await requestDigest("cancel", {
          nonce: bytesOf(challenge.nonce ?? "", protocol.nonce_bytes),
          ticket_hash: hexOf(opened.name),
          issuer_hash: await sha256(issuer),
        }),
      ),
    });
    expect(result.error).toBe("consumed");
    expect(result.state).toBe("consumed");
    const row = await dumpTicket(opened.name);
    expect(row.state).toBe("consumed");
    expect(row.envelope).toBeNull();
  });

  it("the same envelope create is idempotent and a different one conflicts", async () => {
    const opened = await openTicket("idemc");
    const again = await opened.stub.create({
      ticket: opened.ticket,
      issuer_capability: opened.issuer,
      envelope: opened.envelope,
    });
    expect(again).toEqual({ v: 1, state: "open", expires_at: opened.expiresAt });
    const other = exampleEnvelope(`${CIPHERTEXT}!`);
    const conflict = await opened.stub.create({
      ticket: opened.ticket,
      issuer_capability: opened.issuer,
      envelope: other,
    });
    expect(conflict.error).toBe("conflict");
    expect((await dumpTicket(opened.name)).envelope).toBe(opened.envelope);
  });

  it("confirm without a session does not bind", async () => {
    const opened = await openTicket("nosess");
    const who = await receiver();
    const challenge = await opened.stub.challenge({ purpose: "confirm" });
    const missing = exampleBytes("nosesss");
    const result = await finishConfirm(env, {
      ticket: opened.ticket,
      sessionCapability: encodeB64Url(missing),
      confirm: true,
      nonce: challenge.nonce ?? "",
      digest: await confirmDigest({
        nonce: challenge.nonce ?? "",
        sessionHash: encodeHex(await sha256(missing)),
        ticketHash: opened.name,
        pubkey: who.raw,
      }),
    });
    expect(result.error).toBe("session_not_found");
    const row = await dumpTicket(opened.name);
    expect(row.state).toBe("open");
    expect(row.envelope).toBe(opened.envelope);
  });

  it("drops the oldest confirm nonce past the cap", async () => {
    const who = await receiver();
    const opened = await openTicket("noncap");
    const session = await sessionHash("noncaps");
    const nonces: string[] = [];
    for (let i = 0; i < protocol.confirm_nonce_cap + 1; i++) {
      const challenge = await opened.stub.challenge({ purpose: "confirm" });
      nonces.push(challenge.nonce ?? "");
    }
    const stale = await opened.stub.confirm({
      confirm: true,
      pubkey: who.b64,
      sessionHash: session,
      nonce: nonces[0],
      digest: await confirmDigest({
        nonce: nonces[0] ?? "",
        sessionHash: session,
        ticketHash: opened.name,
        pubkey: who.raw,
      }),
    });
    expect(stale.error).toBe("unauthorized");
    expect((await dumpTicket(opened.name)).state).toBe("open");
    const latest = nonces[nonces.length - 1] ?? "";
    const accepted = await opened.stub.confirm({
      confirm: true,
      pubkey: who.b64,
      sessionHash: session,
      nonce: latest,
      digest: await confirmDigest({
        nonce: latest,
        sessionHash: session,
        ticketHash: opened.name,
        pubkey: who.raw,
      }),
    });
    expect(accepted.state).toBe("bound");
  });

  it("an unauthenticated challenge does not replace a live op nonce", async () => {
    const { who, opened } = await bound("liveop");
    const nonce = await redeem(opened, who);
    const again = await opened.stub.challenge({ purpose: "op" });
    expect(again.nonce).toBe(nonce);
    expect((await dumpTicket(opened.name)).op_nonce).toBe(nonce);
    const signature = await signedRead({ who, nonce, ticketHash: opened.name, counter: 0 });
    const [read, raced] = await Promise.all([
      opened.stub.read({ pubkey: who.b64, nonce, counter: 0, signature, origin: ORIGIN }),
      opened.stub.challenge({ purpose: "op" }),
    ]);
    expect(read.envelope).toBe(opened.envelope);
    expect(read.state).toBe("bound");
    expect(raced.error).toBeUndefined();
    const row = await dumpTicket(opened.name);
    expect(row.op).toBe(1);
    expect(row.envelope).toBe(opened.envelope);
    const hash = row.envelope_sha256 ?? "";
    const ackNonce = (await opened.stub.challenge({ purpose: "op" })).nonce ?? "";
    expect((await dumpTicket(opened.name)).op_nonce).toBe(ackNonce);
    const ackSignature = await signedAck({
      who,
      nonce: ackNonce,
      ticketHash: opened.name,
      counter: 1,
      envelopeHash: hash,
    });
    const [ack, ackRace] = await Promise.all([
      opened.stub.ack({
        pubkey: who.b64,
        nonce: ackNonce,
        counter: 1,
        signature: ackSignature,
        origin: ORIGIN,
      }),
      opened.stub.challenge({ purpose: "op" }),
    ]);
    expect(ack.state).toBe("consumed");
    expect(ack.envelope).toBeUndefined();
    expect(ackRace.error).toBeUndefined();
    const consumed = await dumpTicket(opened.name);
    expect(consumed.state).toBe("consumed");
    expect(consumed.envelope).toBeNull();
  });

  it("an unauthenticated cancel challenge does not replace a live cancel nonce", async () => {
    const opened = await openTicket("livecan");
    const first = await opened.stub.challenge({ purpose: "cancel" });
    const second = await opened.stub.challenge({ purpose: "cancel" });
    expect(second.nonce).toBe(first.nonce);
    const issuer = exampleBytes("livecani");
    const { requestDigest } = await import("../src/sign");
    const digest = encodeB64Url(
      await requestDigest("cancel", {
        nonce: bytesOf(first.nonce ?? "", protocol.nonce_bytes),
        ticket_hash: hexOf(opened.name),
        issuer_hash: await sha256(issuer),
      }),
    );
    const [cancelled, raced] = await Promise.all([
      opened.stub.cancel({
        issuer_capability: encodeB64Url(issuer),
        nonce: first.nonce ?? "",
        digest,
      }),
      opened.stub.challenge({ purpose: "cancel" }),
    ]);
    expect(cancelled.state).toBe("cancelled");
    expect(raced.error).toBeUndefined();
    const row = await dumpTicket(opened.name);
    expect(row.state).toBe("cancelled");
    expect(row.envelope).toBeNull();
  });
});
