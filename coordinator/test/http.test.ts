import { SELF } from "cloudflare:test";
import { expect, it, vi } from "vitest";
import { encodeB64Url, encodeHex, sha256 } from "../src/bytes";
import { clearLogs, logEvent, recentLogs, type LogFields } from "../src/log";
import { protocol } from "../src/protocol";
import pageSource from "../public/p.html?raw";
import {
  CIPHERTEXT,
  ORIGIN,
  PASSPHRASE,
  SHARE_URI,
  confirmDigest,
  dumpTicket,
  exampleBytes,
  exampleEnvelope,
  openSession,
  openTicket,
  post,
  receiver,
  redeem,
  signedAck,
  signedRead,
} from "./support";

it("GET does not touch ticket state and does not echo the query", async () => {
  const opened = await openTicket("getone");
  const before = await dumpTicket(opened.name);
  const response = await SELF.fetch(`${ORIGIN}/v1/tickets/preview?ticket=${opened.ticket}`, { method: "GET" });
  expect(response.status).toBe(405);
  expect(response.headers.get("cache-control")).toBe("no-store");
  const text = await response.text();
  expect(JSON.parse(text)).toEqual({ v: 1, error: "bad_request" });
  expect(text).not.toContain(opened.ticket);
  expect(text).not.toContain(CIPHERTEXT);
  expect(text).not.toContain(PASSPHRASE);
  expect(text).not.toContain(SHARE_URI);
  expect(await dumpTicket(opened.name)).toEqual(before);

  const absent = exampleBytes("getnone");
  const name = encodeHex(await sha256(absent));
  const missing = await SELF.fetch(`${ORIGIN}/v1/tickets/read?ticket=${encodeB64Url(absent)}`, { method: "GET" });
  expect(missing.status).toBe(405);
  expect(await missing.text()).not.toContain(encodeB64Url(absent));
  const row = await dumpTicket(name);
  expect(row.state).toBeNull();
  expect(row.alarm).toBeNull();
});

it("preview POST has no side effects and drops unknown fields", async () => {
  const opened = await openTicket("postpre");
  const before = await dumpTicket(opened.name);
  const preview = await post(protocol.routes.ticket_preview, { v: 1, ticket: opened.ticket });
  expect(preview.status).toBe(200);
  expect(preview.headers.get("cache-control")).toBe("no-store");
  expect(preview.json).toEqual({ v: 1, state: "open", expires_at: before.expires_at });
  expect(preview.text).not.toContain(CIPHERTEXT);
  expect(preview.text).not.toContain("argon2id");
  expect(await dumpTicket(opened.name)).toEqual(before);

  const unknown = await post(protocol.routes.ticket_preview, {
    v: 1,
    ticket: opened.ticket,
    passphrase: PASSPHRASE,
    uri: SHARE_URI,
  });
  expect(unknown.status).toBe(400);
  expect(unknown.json).toEqual({ v: 1, error: "unsupported_version" });
  expect(unknown.text).not.toContain(PASSPHRASE);
  expect(unknown.text).not.toContain(SHARE_URI);
  expect(await dumpTicket(opened.name)).toEqual(before);

  const version = await post(protocol.routes.ticket_preview, { v: 2, ticket: opened.ticket });
  expect(version.json).toEqual({ v: 1, error: "unsupported_version" });
  expect(await dumpTicket(opened.name)).toEqual(before);
});

it("confirm false over HTTP leaves the ticket open", async () => {
  const opened = await openTicket("httpno");
  const before = await dumpTicket(opened.name);
  const response = await post(protocol.routes.ticket_confirm, {
    v: 1,
    ticket: opened.ticket,
    session_capability: encodeB64Url(exampleBytes("httpnos")),
    confirm: false,
    nonce: "",
    digest: "",
  });
  expect(response.status).toBe(400);
  expect(response.json).toEqual({
    v: 1,
    state: "open",
    error: "confirm_required",
    expires_at: before.expires_at,
  });
  expect(Object.keys(response.json).every((key) => (protocol.page_fields as readonly string[]).includes(key))).toBe(
    true,
  );
  expect(await dumpTicket(opened.name)).toEqual(before);
});

it("signed HTTP read and ack do not trust the socket", async () => {
  const who = await receiver();
  const session = await openSession("https", who);
  const opened = await openTicket("httpt");
  const challenge = await post(protocol.routes.ticket_challenge, {
    v: 1,
    ticket: opened.ticket,
    purpose: "confirm",
  });
  const confirmed = await post(protocol.routes.ticket_confirm, {
    v: 1,
    ticket: opened.ticket,
    session_capability: session.capability,
    confirm: true,
    nonce: challenge.json.nonce,
    digest: await confirmDigest({
      nonce: String(challenge.json.nonce),
      sessionHash: session.name,
      ticketHash: opened.name,
      pubkey: who.raw,
    }),
  });
  expect(confirmed.status).toBe(200);
  expect(confirmed.json.state).toBe("bound");
  expect(confirmed.json.envelope).toBeUndefined();
  expect(confirmed.json.pubkey).toBeUndefined();
  expect(confirmed.json.hint).toBeUndefined();
  for (const key of Object.keys(confirmed.json)) {
    expect(protocol.page_fields).toContain(key);
  }
  const row = await dumpTicket(opened.name);
  expect(row.envelope).toBe(opened.envelope);
  const nonce = await redeem(opened, who);
  const wrongOrigin = await post(protocol.routes.ticket_read, {
    v: 1,
    ticket: opened.ticket,
    pubkey: who.b64,
    nonce,
    counter: 0,
    signature: await signedRead({
      who,
      nonce,
      ticketHash: opened.name,
      counter: 0,
      origin: "http://127.0.0.1",
    }),
  });
  expect(wrongOrigin.json.error).toBe("unauthorized");
  expect(wrongOrigin.text).not.toContain(CIPHERTEXT);
  expect((await dumpTicket(opened.name)).op).toBe(0);
  expect((await dumpTicket(opened.name)).op_nonce).toBe(nonce);
  const read = await post(protocol.routes.ticket_read, {
    v: 1,
    ticket: opened.ticket,
    pubkey: who.b64,
    nonce,
    counter: 0,
    signature: await signedRead({ who, nonce, ticketHash: opened.name, counter: 0 }),
  });
  expect(read.status).toBe(200);
  expect(read.json.envelope).toBe(opened.envelope);
  expect(read.json.state).toBe("bound");
  const hash = row.envelope_sha256 ?? "";
  const ackNonce = (await opened.stub.challenge({ purpose: "op" })).nonce ?? "";
  const ack = await post(protocol.routes.ticket_ack, {
    v: 1,
    ticket: opened.ticket,
    pubkey: who.b64,
    nonce: ackNonce,
    counter: 1,
    signature: await signedAck({
      who,
      nonce: ackNonce,
      ticketHash: opened.name,
      counter: 1,
      envelopeHash: hash,
    }),
  });
  expect(ack.status).toBe(200);
  expect(ack.json).toEqual({ v: 1, state: "consumed" });
  expect(ack.text).not.toContain(CIPHERTEXT);
  const after = await dumpTicket(opened.name);
  expect(after.state).toBe("consumed");
  expect(after.envelope).toBeNull();
});

it("the fourth create from one source writes nothing", async () => {
  const source = "192.0.2.240";
  for (let i = 0; i < 3; i++) {
    const secret = exampleBytes(`rate${i}`);
    const response = await post(
      protocol.routes.tickets,
      {
        v: 1,
        ticket: encodeB64Url(secret),
        issuer_capability: encodeB64Url(exampleBytes(`rate${i}i`)),
        envelope: exampleEnvelope(),
      },
      source,
    );
    expect(response.status).toBe(200);
    expect(response.json.state).toBe("open");
    expect(response.text).not.toContain(CIPHERTEXT);
    expect(response.text).not.toContain(encodeB64Url(secret));
  }
  const secret = exampleBytes("rate3");
  const denied = await post(
    protocol.routes.tickets,
    {
      v: 1,
      ticket: encodeB64Url(secret),
      issuer_capability: encodeB64Url(exampleBytes("rate3i")),
      envelope: exampleEnvelope(),
    },
    source,
  );
  expect(denied.status).toBe(429);
  expect(denied.json).toEqual({ v: 1, error: "rate_limited" });
  expect(denied.text).not.toContain(encodeB64Url(secret));
  const row = await dumpTicket(encodeHex(await sha256(secret)));
  expect(row.state).toBeNull();
  expect(row.alarm).toBeNull();
});

it("logs and error bodies omit example material", async () => {
  clearLogs();
  const opened = await openTicket("logme");
  logEvent("result", {
    route: "tickets",
    status: 400,
    error: "bad_request",
    ...({ ticket: opened.ticket, envelope: opened.envelope, passphrase: PASSPHRASE } as object),
  } as LogFields);
  const direct = recentLogs().at(-1) ?? "";
  expect(direct).not.toContain(opened.ticket);
  expect(direct).not.toContain(PASSPHRASE);
  expect(direct).not.toContain(CIPHERTEXT);
  expect(direct).toContain("bad_request");

  const lines: string[] = [];
  const spy = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    lines.push(args.map((arg) => String(arg)).join(" "));
  });
  try {
    const response = await post(protocol.routes.ticket_preview, {
      v: 1,
      ticket: opened.ticket,
      passphrase: PASSPHRASE,
      uri: SHARE_URI,
    });
    expect(response.text).not.toContain(opened.ticket);
    expect(response.text).not.toContain(PASSPHRASE);
  } finally {
    spy.mockRestore();
  }
  const logged = lines.join("\n");
  expect(logged).toContain("ticket_preview");
  expect(logged).not.toContain(opened.ticket);
  expect(logged).not.toContain(CIPHERTEXT);
  expect(logged).not.toContain(PASSPHRASE);
  expect(logged).not.toContain(SHARE_URI);
  expect(logged).not.toContain("argon2id");
});

it("serves a static page with no pairing script", async () => {
  const opened = await openTicket("page");
  const before = await dumpTicket(opened.name);
  for (const word of protocol.browser_forbidden_identifiers) {
    expect(pageSource.includes(word)).toBe(false);
  }
  expect(pageSource).not.toContain("<script");
  const response = await SELF.fetch(`${ORIGIN}/p`);
  expect(response.status).toBe(200);
  const html = await response.text();
  expect(html).toContain("Static pairing shell");
  for (const word of protocol.browser_forbidden_identifiers) {
    expect(html.includes(word)).toBe(false);
  }
  expect(html).not.toContain("<script");
  expect(await dumpTicket(opened.name)).toEqual(before);
});

it("a declared oversized body is refused before a durable object write", async () => {
  const secret = exampleBytes("toobig");
  const response = await SELF.fetch(`${ORIGIN}${protocol.routes.tickets}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "content-length": String(protocol.limits.request_max_bytes + 1),
      "CF-Connecting-IP": "192.0.2.241",
    },
    body: JSON.stringify({ v: 1 }),
  });
  expect(response.status).toBe(413);
  expect(await response.json()).toEqual({ v: 1, error: "too_large" });
  const row = await dumpTicket(encodeHex(await sha256(secret)));
  expect(row.state).toBeNull();
});
