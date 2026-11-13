import { SELF } from "cloudflare:test";
import { expect, it } from "vitest";
import { encodeB64Url, encodeHex, fingerprint, sha256 } from "../src/bytes";
import {
  confirmTicket,
  mount,
  previewTicketText,
  sessionCapabilityFromHash,
  ticketFromText,
  type ConfirmButton,
  type PagePost,
  type TextSink,
  type TicketField,
} from "../src/page";
import pageSource from "../src/page.ts?raw";
import servedSource from "../public/page.js?raw";
import qrSource from "../public/jsQR.js?raw";
import { protocol } from "../src/protocol";
import {
  CIPHERTEXT,
  ORIGIN,
  PASSPHRASE,
  SHARE_URI,
  confirmDigest,
  dumpTicket,
  exampleBytes,
  openSession,
  openTicket,
  post,
  receiver,
} from "./support";

const FORBIDDEN = ["decrypt", "passphrase", "ciphertext", "argon2id", "privateKey"] as const;

function textSink(): TextSink {
  return { textContent: "" };
}

function field(): TicketField & { emit(): void } {
  let listener: (() => void) | null = null;
  return {
    value: "",
    addEventListener(_type: string, fn: () => void) {
      listener = fn;
    },
    emit() {
      listener?.();
    },
  };
}

function button(): ConfirmButton & { emit(): void } {
  let listener: (() => void) | null = null;
  return {
    disabled: true,
    addEventListener(_type: string, fn: () => void) {
      listener = fn;
    },
    emit() {
      listener?.();
    },
  };
}

it("decode path calls ticket preview only", async () => {
  const ticket = encodeB64Url(exampleBytes("scan"));
  const calls: { path: string; body: Record<string, unknown> }[] = [];
  const preview = await previewTicketText(async (path, body) => {
    calls.push({ path, body });
    return { v: protocol.version, state: "open" };
  }, `noise ${protocol.qr.ticket_prefix}${ticket} tail`);
  expect(preview).toEqual({ v: protocol.version, state: "open" });
  expect(calls).toEqual([{ path: protocol.routes.ticket_preview, body: { v: protocol.version, ticket } }]);
  expect(calls[0]?.body).not.toHaveProperty("confirm");
  expect(calls.map((call) => call.path)).not.toContain(protocol.routes.ticket_confirm);

  let called = false;
  const missed = await previewTicketText(async () => {
    called = true;
    return {};
  }, "hello");
  expect(missed).toBeNull();
  expect(called).toBe(false);
  expect(ticketFromText("hello")).toBeNull();
  expect(sessionCapabilityFromHash("")).toBeNull();
});

it("confirm callback sends confirm true", async () => {
  const ticket = encodeB64Url(exampleBytes("conf"));
  const capability = encodeB64Url(exampleBytes("confs"));
  const pubkey = new Uint8Array(protocol.pubkey_bytes).fill(7);
  const nonce = encodeB64Url(new Uint8Array(protocol.nonce_bytes).fill(9));
  const calls: { path: string; body: Record<string, unknown> }[] = [];
  const confirmed = await confirmTicket(
    async (path, body) => {
      calls.push({ path, body });
      if (path === protocol.routes.ticket_challenge) return { v: protocol.version, nonce };
      return { v: protocol.version, state: "bound" };
    },
    { ticket, sessionCapability: capability, pubkey: encodeB64Url(pubkey) },
  );
  expect(confirmed.state).toBe("bound");
  expect(calls.map((call) => call.path)).toEqual([protocol.routes.ticket_challenge, protocol.routes.ticket_confirm]);
  expect(calls[1]?.body.confirm).toBe(true);
  expect(calls[1]?.body).toMatchObject({
    v: protocol.version,
    ticket,
    session_capability: capability,
    nonce,
  });
  expect(calls[1]?.body.digest).toBe(
    await confirmDigest({
      nonce,
      sessionHash: encodeHex(await sha256(exampleBytes("confs"))),
      ticketHash: encodeHex(await sha256(exampleBytes("conf"))),
      pubkey,
    }),
  );
  expect(calls.some((call) => call.path === protocol.routes.ticket_preview)).toBe(false);
  expect(calls.some((call) => call.path === protocol.routes.ticket_read)).toBe(false);
  expect(calls.some((call) => call.path === protocol.routes.ticket_ack)).toBe(false);

  const paths: string[] = [];
  const refused = await confirmTicket(
    async (path) => {
      paths.push(path);
      return { v: protocol.version, error: "ticket_not_found" };
    },
    { ticket, sessionCapability: capability, pubkey: encodeB64Url(pubkey) },
  );
  expect(paths).toEqual([protocol.routes.ticket_challenge]);
  expect(refused.error).toBe("ticket_not_found");
});

it("page script has no decrypt", () => {
  for (const word of FORBIDDEN) {
    expect(pageSource.includes(word), word).toBe(false);
    expect(servedSource.includes(word), `served ${word}`).toBe(false);
    expect(qrSource.includes(word), `qr ${word}`).toBe(false);
  }
  for (const source of [pageSource, servedSource]) {
    expect(source).toContain("confirm: true");
    expect(source).toContain(protocol.routes.ticket_preview);
    expect(source).toContain(protocol.routes.session_preview);
    expect(source).toContain(protocol.routes.ticket_confirm);
    expect(source).toContain(protocol.qr.ticket_prefix);
    expect(source).toContain(protocol.signatures.confirm.scope);
    expect(source).not.toContain(protocol.routes.ticket_read);
    expect(source).not.toContain(protocol.routes.ticket_ack);
    expect(source).not.toContain('method: "GET"');
    expect(source).not.toContain("<input");
  }
  expect(servedSource).toContain("jsQR");
});

it("scan and paste preview, and Confirm sends confirm true", async () => {
  const token = encodeB64Url(exampleBytes("wire"));
  const capability = encodeB64Url(exampleBytes("wires"));
  const pubkey = encodeB64Url(new Uint8Array(protocol.pubkey_bytes).fill(4));
  const nonce = encodeB64Url(new Uint8Array(protocol.nonce_bytes).fill(5));
  const calls: { path: string; body: Record<string, unknown> }[] = [];
  const postMock: PagePost = async (path, body) => {
    calls.push({ path, body });
    if (path === protocol.routes.session_preview) {
      return { v: protocol.version, fingerprint: "abcd-ef01-2345-6789", pubkey };
    }
    if (path === protocol.routes.ticket_preview) return { v: protocol.version, state: "open", expires_at: 1 };
    if (path === protocol.routes.ticket_challenge) return { v: protocol.version, nonce };
    return { v: protocol.version, state: "bound", fingerprint: "abcd-ef01-2345-6789" };
  };
  const fingerprintSink = textSink();
  const status = textSink();
  const ticket = field();
  const confirm = button();
  let settled = Promise.resolve();
  await mount({
    hash: `#${protocol.qr.session_fragment_parameter}=${capability}`,
    fingerprint: fingerprintSink,
    status,
    ticket,
    confirm,
    camera: null,
    post: postMock,
    watch: (onText) => {
      onText(`${protocol.qr.ticket_prefix}${token}`);
    },
    onSettle: (done) => {
      settled = done;
    },
  });
  expect(fingerprintSink.textContent).toBe("abcd-ef01-2345-6789");
  await settled;
  expect(calls.map((call) => call.path)).toEqual([protocol.routes.session_preview, protocol.routes.ticket_preview]);
  expect(calls[1]?.body).toEqual({ v: protocol.version, ticket: token });
  expect(calls[1]?.body).not.toHaveProperty("confirm");
  expect(confirm.disabled).toBe(false);
  expect(status.textContent).toBe("Ticket is open. Press Confirm to bind.");

  const pasted = encodeB64Url(exampleBytes("wirep"));
  ticket.value = `${protocol.qr.ticket_prefix}${pasted}`;
  ticket.emit();
  await settled;
  expect(calls.map((call) => call.path)).toEqual([
    protocol.routes.session_preview,
    protocol.routes.ticket_preview,
    protocol.routes.ticket_preview,
  ]);
  expect(calls[2]?.body).toEqual({ v: protocol.version, ticket: pasted });

  confirm.emit();
  await settled;
  const confirmCall = calls.filter((call) => call.path === protocol.routes.ticket_confirm);
  expect(confirmCall).toHaveLength(1);
  expect(confirmCall[0]?.body.confirm).toBe(true);
  expect(confirmCall[0]?.body.ticket).toBe(pasted);
  expect(confirmCall[0]?.body.session_capability).toBe(capability);
  expect(fingerprintSink.textContent).toBe("abcd-ef01-2345-6789");
  expect(status.textContent).toBe("bound");
});

it("preview does not bind and confirm true does", async () => {
  const who = await receiver();
  const session = await openSession("phsess", who);
  const opened = await openTicket("phtkt");
  const before = await dumpTicket(opened.name);
  const calls: { path: string; body: Record<string, unknown> }[] = [];
  const transport: PagePost = async (path, body) => {
    calls.push({ path, body });
    const response = await post(path, body);
    expect(response.text).not.toContain(CIPHERTEXT);
    expect(response.text).not.toContain(PASSPHRASE);
    expect(response.text).not.toContain(SHARE_URI);
    expect(response.text).not.toContain(opened.ticket);
    return response.json;
  };
  const sessionBody = await transport(protocol.routes.session_preview, {
    v: protocol.version,
    session_capability: session.capability,
  });
  expect(sessionBody.fingerprint).toBe(await fingerprint(who.raw));
  const preview = await previewTicketText(transport, `${protocol.qr.ticket_prefix}${opened.ticket}`);
  expect(preview?.state).toBe("open");
  expect(calls.map((call) => call.path)).toEqual([protocol.routes.session_preview, protocol.routes.ticket_preview]);
  expect(await dumpTicket(opened.name)).toEqual(before);

  const confirmed = await confirmTicket(transport, {
    ticket: opened.ticket,
    sessionCapability: session.capability,
    pubkey: String(sessionBody.pubkey),
  });
  expect(confirmed.state).toBe("bound");
  expect(confirmed.fingerprint).toBe(sessionBody.fingerprint);
  expect(confirmed.envelope).toBeUndefined();
  const confirmCall = calls.find((call) => call.path === protocol.routes.ticket_confirm);
  expect(confirmCall?.body.confirm).toBe(true);
  const after = await dumpTicket(opened.name);
  expect(after.state).toBe("bound");
  expect(after.envelope).toBe(opened.envelope);

  const script = await SELF.fetch(`${ORIGIN}/page.js`);
  expect(script.status).toBe(200);
  expect(await script.text()).not.toContain("decrypt");
  const decoder = await SELF.fetch(`${ORIGIN}/jsQR.js`);
  expect(decoder.status).toBe(200);
});
