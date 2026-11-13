import { DurableObject } from "cloudflare:workers";
import {
  bytesEqual,
  decodeB64Url,
  decodeHex,
  encodeB64Url,
  encodeHex,
  fingerprint,
  originFromUrl,
  randomBytes,
  sha256,
} from "./bytes";
import { protocol, type Hint, type ServerError } from "./protocol";
import { verifySignature, type SignValues } from "./sign";

interface SessionRow {
  pubkey: string | null;
  session_hash: string | null;
  hello_at: number | null;
  expires_at: number | null;
  state: string;
  op: number;
  hello_nonce: string | null;
  wait_nonce: string | null;
  hint_v: number | null;
  hint_state: string | null;
  hint_ticket_hash: string | null;
  hint_seed_nonce: string | null;
  hint_expires_at: number | null;
  origin: string | null;
}

export interface SessionChallengeResult {
  v: number;
  nonce?: string;
  error?: ServerError;
}

export interface HelloResult {
  v: number;
  error?: ServerError;
  fingerprint?: string;
}

export interface SessionPreviewResult {
  v: number;
  fingerprint?: string;
  pubkey?: string;
  error?: ServerError;
}

export interface WaitResult {
  v: number;
  hint?: Hint | null;
  error?: ServerError;
}

function fixed(value: string, size: number): Uint8Array | null {
  const bytes = decodeB64Url(value);
  if (!bytes || bytes.length !== size) return null;
  return bytes;
}

export class SessionDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.setWebSocketAutoResponse(
      new WebSocketRequestResponsePair(protocol.ws_auto_ping, protocol.ws_auto_pong),
    );
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(
        `CREATE TABLE IF NOT EXISTS session (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          pubkey TEXT,
          session_hash TEXT,
          hello_at INTEGER,
          expires_at INTEGER,
          state TEXT NOT NULL,
          op INTEGER NOT NULL,
          hello_nonce TEXT,
          wait_nonce TEXT,
          hint_v INTEGER,
          hint_state TEXT,
          hint_ticket_hash TEXT,
          hint_seed_nonce TEXT,
          hint_expires_at INTEGER,
          origin TEXT
        )`,
      );
    });
  }

  async challenge(input: { sessionHash: string; purpose: string }): Promise<SessionChallengeResult> {
    if (input.purpose !== "hello" && input.purpose !== "wait") {
      return { v: protocol.version, error: "bad_request" };
    }
    if (!/^[0-9a-f]{64}$/.test(input.sessionHash)) {
      return { v: protocol.version, error: "bad_request" };
    }
    const nonce = encodeB64Url(randomBytes(protocol.nonce_bytes));
    this.#ensure(input.sessionHash);
    const row = this.#load();
    if (row?.session_hash && row.session_hash !== input.sessionHash) {
      return { v: protocol.version, error: "forbidden" };
    }
    if (input.purpose === "hello") {
      this.ctx.storage.sql.exec("UPDATE session SET hello_nonce = ? WHERE id = 1", nonce);
    } else {
      this.ctx.storage.sql.exec("UPDATE session SET wait_nonce = ? WHERE id = 1", nonce);
    }
    return { v: protocol.version, nonce };
  }

  async hello(input: {
    sessionHash: string;
    pubkey: string;
    nonce: string;
    signature: string;
    origin: string;
  }): Promise<HelloResult> {
    const pubkey = fixed(input.pubkey, protocol.pubkey_bytes);
    const nonce = fixed(input.nonce, protocol.nonce_bytes);
    const signature = decodeB64Url(input.signature);
    const sessionHash = decodeHex(input.sessionHash);
    if (!pubkey || !nonce || !signature || signature.length !== 64 || !sessionHash || sessionHash.length !== 32) {
      return { v: protocol.version, error: "bad_request" };
    }
    const row = this.#load();
    if (!row || !row.hello_nonce) return { v: protocol.version, error: "unauthorized" };
    const storedNonce = fixed(row.hello_nonce, protocol.nonce_bytes);
    if (!storedNonce || !bytesEqual(storedNonce, nonce)) {
      return { v: protocol.version, error: "unauthorized" };
    }
    const values: SignValues = {
      origin: input.origin,
      server_nonce: nonce,
      receiver_pubkey: pubkey,
      pubkey,
      session_hash: sessionHash,
    };
    const ok = await verifySignature("hello", values, pubkey, signature);
    if (!ok) return { v: protocol.version, error: "unauthorized" };
    const committed = this.#commitHello(input.sessionHash, input.pubkey, input.nonce);
    if (committed.error) return { v: protocol.version, error: committed.error };
    if (committed.schedule) await this.ctx.storage.setAlarm(committed.schedule);
    return { v: protocol.version, fingerprint: await fingerprint(pubkey) };
  }

  async preview(input: { sessionHash: string }): Promise<SessionPreviewResult> {
    const row = this.#load();
    if (!row?.pubkey || row.session_hash !== input.sessionHash || row.state === "expired") {
      return { v: protocol.version, error: "session_not_found" };
    }
    const pubkey = fixed(row.pubkey, protocol.pubkey_bytes);
    if (!pubkey) return { v: protocol.version, error: "session_not_found" };
    return {
      v: protocol.version,
      fingerprint: await fingerprint(pubkey),
      pubkey: row.pubkey,
    };
  }

  async previewPubkey(input: { capability: string }): Promise<{ pubkey: string } | { error: ServerError }> {
    const raw = fixed(input.capability, protocol.capability_bytes);
    if (!raw) return { error: "session_not_found" };
    const sessionHash = encodeHex(await sha256(raw));
    const row = this.#load();
    if (!row?.pubkey || row.session_hash !== sessionHash || row.state === "expired") {
      return { error: "session_not_found" };
    }
    return { pubkey: row.pubkey };
  }

  async notify(hint: Hint): Promise<boolean> {
    if (hint.v !== protocol.version || !this.#hintState(hint.state)) return false;
    if (!/^[0-9a-f]{64}$/.test(hint.ticket_hash)) return false;
    const seed = fixed(hint.seed_nonce, protocol.nonce_bytes);
    if (!seed || !Number.isFinite(hint.expires_at)) return false;
    const row = this.#load();
    if (!row?.pubkey || row.state === "expired") return false;
    this.ctx.storage.sql.exec(
      `UPDATE session
       SET hint_v = ?, hint_state = ?, hint_ticket_hash = ?, hint_seed_nonce = ?, hint_expires_at = ?, expires_at = ?
       WHERE id = 1`,
      hint.v,
      hint.state,
      hint.ticket_hash,
      hint.seed_nonce,
      hint.expires_at,
      hint.expires_at,
    );
    await this.ctx.storage.setAlarm(hint.expires_at);
    const message = JSON.stringify(this.#publicHint(hint));
    for (const socket of this.ctx.getWebSockets()) {
      try {
        socket.send(message);
      } catch {
        // The hint is already stored for wait.
      }
    }
    return true;
  }

  async wait(input: {
    sessionHash: string;
    pubkey: string;
    nonce: string;
    counter: number;
    signature: string;
    origin: string;
  }): Promise<WaitResult> {
    const pubkey = fixed(input.pubkey, protocol.pubkey_bytes);
    const nonce = fixed(input.nonce, protocol.nonce_bytes);
    const signature = decodeB64Url(input.signature);
    const sessionHash = decodeHex(input.sessionHash);
    if (
      !pubkey ||
      !nonce ||
      !signature ||
      signature.length !== 64 ||
      !sessionHash ||
      !Number.isSafeInteger(input.counter) ||
      input.counter < 0
    ) {
      return { v: protocol.version, error: "bad_request" };
    }
    const row = this.#load();
    if (!row?.pubkey || !row.wait_nonce || row.session_hash !== input.sessionHash) {
      return { v: protocol.version, error: "unauthorized" };
    }
    const storedNonce = fixed(row.wait_nonce, protocol.nonce_bytes);
    const storedKey = fixed(row.pubkey, protocol.pubkey_bytes);
    if (!storedNonce || !storedKey || !bytesEqual(storedNonce, nonce) || !bytesEqual(storedKey, pubkey)) {
      return { v: protocol.version, error: "unauthorized" };
    }
    if (Number(row.op) !== input.counter) return { v: protocol.version, error: "conflict" };
    const ok = await verifySignature(
      "wait",
      {
        origin: input.origin,
        server_nonce: nonce,
        receiver_pubkey: pubkey,
        pubkey,
        session_hash: sessionHash,
        counter: input.counter,
      },
      pubkey,
      signature,
    );
    if (!ok) return { v: protocol.version, error: "unauthorized" };
    return this.#commitWait(input.nonce, input.counter);
  }

  async alarm(): Promise<void> {
    const row = this.#load();
    if (!row?.expires_at || row.state === "expired") return;
    if (Date.now() < Number(row.expires_at)) {
      await this.ctx.storage.setAlarm(Number(row.expires_at));
      return;
    }
    this.ctx.storage.sql.exec(
      "UPDATE session SET state = ?, hello_nonce = NULL, wait_nonce = NULL WHERE id = 1",
      "expired",
    );
  }

  async fetch(request: Request): Promise<Response> {
    if (request.headers.get("Upgrade")?.toLowerCase() !== "websocket") {
      return new Response(null, { status: protocol.http.method_not_allowed });
    }
    const sessionHash = request.headers.get(protocol.session_header) ?? "";
    if (!/^[0-9a-f]{64}$/.test(sessionHash)) {
      return new Response(null, { status: protocol.error_status.unauthorized });
    }
    const row = this.#load();
    if (row?.session_hash && row.session_hash !== sessionHash) {
      return new Response(null, { status: protocol.error_status.forbidden });
    }
    this.#ensure(sessionHash);
    const nonce = encodeB64Url(randomBytes(protocol.nonce_bytes));
    const origin = originFromUrl(new URL(request.url));
    this.ctx.storage.sql.exec(
      "UPDATE session SET hello_nonce = ?, origin = ? WHERE id = 1",
      nonce,
      origin,
    );
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    this.ctx.acceptWebSocket(server);
    server.send(
      JSON.stringify({
        v: protocol.version,
        type: protocol.ws_messages[1],
        nonce,
      }),
    );
    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    if (typeof message !== "string") {
      ws.send(JSON.stringify({ v: protocol.version, error: "bad_request" }));
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(message);
    } catch {
      ws.send(JSON.stringify({ v: protocol.version, error: "bad_request" }));
      return;
    }
    if (!parsed || typeof parsed !== "object") {
      ws.send(JSON.stringify({ v: protocol.version, error: "bad_request" }));
      return;
    }
    const body = parsed as Record<string, unknown>;
    if (body.v !== protocol.version || body.type !== protocol.ws_messages[2]) {
      ws.send(JSON.stringify({ v: protocol.version, error: "unsupported_version" }));
      return;
    }
    if (typeof body.pubkey !== "string" || typeof body.signature !== "string") {
      ws.send(JSON.stringify({ v: protocol.version, error: "bad_request" }));
      return;
    }
    const row = this.#load();
    if (!row?.session_hash || !row.hello_nonce || !row.origin) {
      ws.send(JSON.stringify({ v: protocol.version, error: "unauthorized" }));
      return;
    }
    const result = await this.hello({
      sessionHash: row.session_hash,
      pubkey: body.pubkey,
      nonce: row.hello_nonce,
      signature: body.signature,
      origin: row.origin,
    });
    if (result.error) {
      ws.send(JSON.stringify({ v: protocol.version, error: result.error }));
      return;
    }
    ws.send(JSON.stringify({ v: protocol.version, type: protocol.ws_messages[0], fingerprint: result.fingerprint }));
  }

  async webSocketClose(): Promise<void> {
    // Closing the socket does not change ticket state. This object has no ticket write path.
  }

  #commitHello(
    sessionHash: string,
    pubkey: string,
    nonce: string,
  ): { error?: ServerError; schedule?: number } {
    const row = this.#load();
    if (!row || row.hello_nonce !== nonce) return { error: "unauthorized" };
    if (row.session_hash && row.session_hash !== sessionHash) return { error: "forbidden" };
    if (row.pubkey && row.pubkey !== pubkey) return { error: "forbidden" };
    const now = Date.now();
    if (!row.pubkey) {
      const expiresAt = now + protocol.limits.session_ttl_ms;
      this.ctx.storage.sql.exec(
        `UPDATE session
         SET pubkey = ?, session_hash = ?, hello_at = ?, expires_at = ?, state = ?, hello_nonce = NULL
         WHERE id = 1`,
        pubkey,
        sessionHash,
        now,
        expiresAt,
        "active",
      );
      return { schedule: expiresAt };
    }
    this.ctx.storage.sql.exec("UPDATE session SET hello_nonce = NULL WHERE id = 1");
    return {};
  }

  #commitWait(nonce: string, counter: number): WaitResult {
    const row = this.#load();
    if (!row || row.wait_nonce !== nonce || Number(row.op) !== counter) {
      return { v: protocol.version, error: "unauthorized" };
    }
    this.ctx.storage.sql.exec(
      "UPDATE session SET op = ?, wait_nonce = NULL WHERE id = 1",
      Number(row.op) + 1,
    );
    return { v: protocol.version, hint: this.#hint(row) };
  }

  #hint(row: SessionRow): Hint | null {
    if (
      row.hint_v === null ||
      row.hint_state === null ||
      row.hint_ticket_hash === null ||
      row.hint_seed_nonce === null ||
      row.hint_expires_at === null ||
      !this.#hintState(row.hint_state)
    ) {
      return null;
    }
    return {
      v: Number(row.hint_v),
      state: row.hint_state,
      ticket_hash: row.hint_ticket_hash,
      seed_nonce: row.hint_seed_nonce,
      expires_at: Number(row.hint_expires_at),
    };
  }

  #publicHint(hint: Hint): Hint {
    return {
      v: hint.v,
      state: hint.state,
      ticket_hash: hint.ticket_hash,
      seed_nonce: hint.seed_nonce,
      expires_at: hint.expires_at,
    };
  }

  #hintState(state: string): state is Hint["state"] {
    return (protocol.hint_states as readonly string[]).includes(state);
  }

  #ensure(sessionHash: string): void {
    const row = this.#load();
    if (row) return;
    this.ctx.storage.sql.exec(
      "INSERT INTO session (id, session_hash, state, op) VALUES (1, ?, ?, 0)",
      sessionHash,
      "active",
    );
  }

  #load(): SessionRow | null {
    const rows = this.ctx.storage.sql
      .exec(
        `SELECT pubkey, session_hash, hello_at, expires_at, state, op, hello_nonce, wait_nonce,
                hint_v, hint_state, hint_ticket_hash, hint_seed_nonce, hint_expires_at, origin
         FROM session WHERE id = 1`,
      )
      .toArray() as unknown as SessionRow[];
    return rows[0] ?? null;
  }
}
