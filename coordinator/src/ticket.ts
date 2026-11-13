import { DurableObject } from "cloudflare:workers";
import {
  bytesEqual,
  decodeB64Url,
  decodeHex,
  encodeB64Url,
  encodeHex,
  fingerprint,
  randomBytes,
  sha256,
  utf8,
} from "./bytes";
import { checkEnvelope } from "./envelope";
import { protocol, type Hint, type ServerError, type TicketState } from "./protocol";
import { requestDigest, verifySignature } from "./sign";

interface TicketRow {
  state: string;
  created_at: number;
  expires_at: number;
  terminal_at: number | null;
  bound_pubkey: string | null;
  bound_fingerprint: string | null;
  op: number;
  envelope_sha256: string | null;
  issuer_hash: string;
  ticket_hash: string;
  seed_nonce: string | null;
  op_nonce: string | null;
  envelope: string | null;
}

export interface TicketResult {
  v: number;
  state?: TicketState;
  error?: ServerError;
  expires_at?: number;
  fingerprint?: string;
  nonce?: string;
  envelope?: string;
  hint?: Hint;
}

interface CreateInput {
  ticket: string;
  issuer_capability: string;
  envelope: string;
  grant_id?: string;
  grant_source?: string;
}

function fixed(value: string | undefined, size: number): Uint8Array | null {
  if (!value) return null;
  const bytes = decodeB64Url(value);
  if (!bytes || bytes.length !== size) return null;
  return bytes;
}

function terminalError(state: string): ServerError | null {
  if (state === "consumed" || state === "expired" || state === "cancelled") return state;
  return null;
}

export class TicketDO extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(
        `CREATE TABLE IF NOT EXISTS ticket (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          state TEXT NOT NULL,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          terminal_at INTEGER,
          bound_pubkey TEXT,
          bound_fingerprint TEXT,
          op INTEGER NOT NULL,
          envelope_sha256 TEXT,
          issuer_hash TEXT NOT NULL,
          ticket_hash TEXT NOT NULL,
          seed_nonce TEXT,
          op_nonce TEXT,
          envelope TEXT
        )`,
      );
      this.ctx.storage.sql.exec(
        `CREATE TABLE IF NOT EXISTS pending_nonce (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          purpose TEXT NOT NULL,
          value TEXT NOT NULL
        )`,
      );
    });
  }

  async create(input: CreateInput): Promise<TicketResult> {
    const envelopeError = checkEnvelope(input.envelope);
    if (envelopeError) return { v: protocol.version, error: envelopeError };
    const ticket = fixed(input.ticket, protocol.capability_bytes);
    const issuer = fixed(input.issuer_capability, protocol.capability_bytes);
    if (!ticket || !issuer) return { v: protocol.version, error: "bad_request" };
    const ticketHash = encodeHex(await sha256(ticket));
    const issuerHash = encodeHex(await sha256(issuer));
    const envelopeHash = encodeHex(await sha256(utf8(input.envelope)));
    const existing = this.#load();
    const prior = this.#existingCreate(existing, envelopeHash);
    if (prior) return prior;
    if (!input.grant_id || !input.grant_source || !/^source:[0-9a-f]{64}$/.test(input.grant_source)) {
      return { v: protocol.version, error: "unauthorized" };
    }
    let consumed = false;
    try {
      consumed = await this.env.GATE.getByName(input.grant_source).consume(input.grant_id, ticketHash);
    } catch {
      return { v: protocol.version, error: "unauthorized" };
    }
    if (!consumed) return { v: protocol.version, error: "unauthorized" };
    const written = this.#commitCreate({
      ticketHash,
      issuerHash,
      envelopeHash,
      envelope: input.envelope,
    });
    if (written.kind === "created") {
      await this.ctx.storage.setAlarm(written.expiresAt);
      return { v: protocol.version, state: "open", expires_at: written.expiresAt };
    }
    if (written.kind === "idempotent") {
      return { v: protocol.version, state: "open", expires_at: written.expiresAt };
    }
    if (written.kind === "terminal") return { v: protocol.version, error: written.error, state: written.state };
    return { v: protocol.version, error: "conflict" };
  }

  async preview(): Promise<TicketResult> {
    const row = this.#load();
    if (!row) return { v: protocol.version, error: "ticket_not_found" };
    return {
      v: protocol.version,
      state: this.#state(row.state),
      expires_at: Number(row.expires_at),
      fingerprint: row.bound_fingerprint ?? undefined,
    };
  }

  async challenge(input: {
    purpose: string;
    pubkey?: string;
    signature?: string;
    origin?: string;
  }): Promise<TicketResult> {
    if (!(protocol.challenge_purposes as readonly string[]).includes(input.purpose)) {
      return { v: protocol.version, error: "bad_request" };
    }
    const row = this.#load();
    if (!row) return { v: protocol.version, error: "ticket_not_found" };
    if (input.purpose === "confirm") {
      const nonce = encodeB64Url(randomBytes(protocol.nonce_bytes));
      this.#addConfirmNonce(nonce);
      return { v: protocol.version, nonce };
    }
    if (input.purpose === "cancel") {
      const existing = this.#nonceValue("cancel");
      if (existing) return { v: protocol.version, nonce: existing };
      const nonce = encodeB64Url(randomBytes(protocol.nonce_bytes));
      this.ctx.storage.sql.exec("INSERT INTO pending_nonce (purpose, value) VALUES ('cancel', ?)", nonce);
      return { v: protocol.version, nonce };
    }
    if (input.signature) return this.#redeem(row, input.pubkey, input.signature, input.origin);
    return this.#issueOpNonce(row);
  }

  async confirm(input: {
    confirm: boolean;
    pubkey?: string;
    sessionHash?: string;
    nonce?: string;
    digest?: string;
  }): Promise<TicketResult> {
    const row = this.#load();
    if (!row) return { v: protocol.version, error: "ticket_not_found" };
    if (input.confirm !== true) {
      const terminal = terminalError(row.state);
      if (terminal) return { v: protocol.version, error: terminal, state: this.#state(row.state) };
      return {
        v: protocol.version,
        error: "confirm_required",
        state: this.#state(row.state),
        expires_at: Number(row.expires_at),
      };
    }
    const pubkey = fixed(input.pubkey, protocol.pubkey_bytes);
    const nonce = fixed(input.nonce, protocol.nonce_bytes);
    const digest = fixed(input.digest, 32);
    const sessionHash = input.sessionHash ? decodeHex(input.sessionHash) : null;
    const ticketHash = decodeHex(row.ticket_hash);
    if (!pubkey || !nonce || !digest || digest.length !== 32 || !sessionHash || !ticketHash) {
      return { v: protocol.version, error: "bad_request" };
    }
    const expected = await requestDigest("confirm", {
      nonce,
      session_hash: sessionHash,
      ticket_hash: ticketHash,
      pubkey,
    });
    if (!bytesEqual(expected, digest)) return { v: protocol.version, error: "unauthorized" };
    const printed = await fingerprint(pubkey);
    return this.#commitConfirm(input.pubkey ?? "", printed, input.nonce ?? "");
  }

  async read(input: {
    pubkey: string;
    nonce: string;
    counter: number;
    signature: string;
    origin: string;
  }): Promise<TicketResult> {
    return this.#signedRead(input, false);
  }

  async ack(input: {
    pubkey: string;
    nonce: string;
    counter: number;
    signature: string;
    origin: string;
  }): Promise<TicketResult> {
    return this.#signedRead(input, true);
  }

  async status(input: { issuer_capability: string }): Promise<TicketResult> {
    const issuer = fixed(input.issuer_capability, protocol.capability_bytes);
    const row = this.#load();
    if (!row) return { v: protocol.version, error: "ticket_not_found" };
    if (!issuer) return { v: protocol.version, error: "unauthorized" };
    const actual = await sha256(issuer);
    const stored = decodeHex(row.issuer_hash);
    if (!stored || !bytesEqual(stored, actual)) return { v: protocol.version, error: "unauthorized" };
    return {
      v: protocol.version,
      state: this.#state(row.state),
      expires_at: Number(row.expires_at),
      fingerprint: row.bound_fingerprint ?? undefined,
    };
  }

  async cancel(input: { issuer_capability: string; nonce: string; digest: string }): Promise<TicketResult> {
    const issuer = fixed(input.issuer_capability, protocol.capability_bytes);
    const nonce = fixed(input.nonce, protocol.nonce_bytes);
    const digest = fixed(input.digest, 32);
    const row = this.#load();
    if (!row) return { v: protocol.version, error: "ticket_not_found" };
    if (!issuer || !nonce || !digest) return { v: protocol.version, error: "bad_request" };
    const issuerHash = await sha256(issuer);
    const storedIssuer = decodeHex(row.issuer_hash);
    const ticketHash = decodeHex(row.ticket_hash);
    if (!storedIssuer || !ticketHash || !bytesEqual(storedIssuer, issuerHash)) {
      return { v: protocol.version, error: "unauthorized" };
    }
    const expected = await requestDigest("cancel", {
      nonce,
      ticket_hash: ticketHash,
      issuer_hash: issuerHash,
    });
    if (!bytesEqual(expected, digest)) return { v: protocol.version, error: "unauthorized" };
    return this.#commitCancel(input.nonce);
  }

  async alarm(): Promise<void> {
    const row = this.#load();
    if (!row || (row.state !== "open" && row.state !== "bound")) return;
    const now = Date.now();
    if (now < Number(row.expires_at)) {
      await this.ctx.storage.setAlarm(Number(row.expires_at));
      return;
    }
    this.#expire(now);
  }

  async #signedRead(
    input: { pubkey: string; nonce: string; counter: number; signature: string; origin: string },
    isAck: boolean,
  ): Promise<TicketResult> {
    const pubkey = fixed(input.pubkey, protocol.pubkey_bytes);
    const nonce = fixed(input.nonce, protocol.nonce_bytes);
    const signature = decodeB64Url(input.signature);
    if (!pubkey || !nonce || !signature || signature.length !== 64 || !Number.isSafeInteger(input.counter) || input.counter < 0) {
      return { v: protocol.version, error: "bad_request" };
    }
    const row = this.#load();
    if (!row) return { v: protocol.version, error: "ticket_not_found" };
    const storedNonce = row.op_nonce ? fixed(row.op_nonce, protocol.nonce_bytes) : null;
    const ticketHash = decodeHex(row.ticket_hash);
    const envelopeHash = row.envelope_sha256 ? decodeHex(row.envelope_sha256) : null;
    if (!storedNonce || !ticketHash || !bytesEqual(storedNonce, nonce)) {
      return { v: protocol.version, error: "unauthorized" };
    }
    if (isAck && !envelopeHash) return { v: protocol.version, error: "unauthorized" };
    const name = isAck ? "ack" : "read";
    const ok = await verifySignature(
      name,
      {
        origin: input.origin,
        server_nonce: nonce,
        ticket_hash: ticketHash,
        receiver_pubkey: pubkey,
        counter: input.counter,
        envelope_sha256: envelopeHash ?? undefined,
      },
      pubkey,
      signature,
    );
    if (!ok) return { v: protocol.version, error: "unauthorized" };
    if (isAck) return this.#commitAck(input.pubkey, input.nonce, input.counter);
    return this.#commitRead(input.pubkey, input.nonce, input.counter);
  }

  async #redeem(
    row: TicketRow,
    pubkeyB64: string | undefined,
    signatureB64: string | undefined,
    origin: string | undefined,
  ): Promise<TicketResult> {
    const pubkey = fixed(pubkeyB64, protocol.pubkey_bytes);
    const signature = signatureB64 ? decodeB64Url(signatureB64) : null;
    const seed = row.seed_nonce ? fixed(row.seed_nonce, protocol.nonce_bytes) : null;
    const ticketHash = decodeHex(row.ticket_hash);
    if (!pubkey || !signature || signature.length !== 64 || !seed || !ticketHash || !origin) {
      return { v: protocol.version, error: "bad_request" };
    }
    const ok = await verifySignature(
      "challenge",
      {
        origin,
        server_nonce: seed,
        ticket_hash: ticketHash,
        receiver_pubkey: pubkey,
      },
      pubkey,
      signature,
    );
    if (!ok) return { v: protocol.version, error: "unauthorized" };
    return this.#commitRedeem(pubkeyB64 ?? "", row.seed_nonce ?? "");
  }

  #existingCreate(existing: TicketRow | null, envelopeHash: string): TicketResult | null {
    if (!existing) return null;
    if (existing.state === "open" && existing.envelope_sha256 === envelopeHash) {
      return { v: protocol.version, state: "open", expires_at: Number(existing.expires_at) };
    }
    if (existing.state === "open") return { v: protocol.version, error: "conflict" };
    if (existing.state === "bound") {
      return { v: protocol.version, error: "ticket_bound", state: "bound", expires_at: Number(existing.expires_at) };
    }
    const terminal = terminalError(existing.state);
    return {
      v: protocol.version,
      error: terminal ?? "conflict",
      state: terminal ? this.#state(existing.state) : undefined,
    };
  }

  #commitCreate(input: {
    ticketHash: string;
    issuerHash: string;
    envelopeHash: string;
    envelope: string;
  }):
    | { kind: "created"; expiresAt: number }
    | { kind: "idempotent"; expiresAt: number }
    | { kind: "conflict" }
    | { kind: "terminal"; error: ServerError; state: TicketState } {
    const existing = this.#load();
    if (existing) {
      if (existing.state === "open" && existing.envelope_sha256 === input.envelopeHash) {
        return { kind: "idempotent", expiresAt: Number(existing.expires_at) };
      }
      const terminal = terminalError(existing.state);
      if (terminal) return { kind: "terminal", error: terminal, state: this.#state(existing.state) };
      return { kind: "conflict" };
    }
    const now = Date.now();
    const expiresAt = now + protocol.limits.ticket_ttl_ms;
    this.ctx.storage.sql.exec(
      `INSERT INTO ticket (
        id, state, created_at, expires_at, op, envelope_sha256, issuer_hash, ticket_hash, envelope
      ) VALUES (1, ?, ?, ?, 0, ?, ?, ?, ?)`,
      "open",
      now,
      expiresAt,
      input.envelopeHash,
      input.issuerHash,
      input.ticketHash,
      input.envelope,
    );
    return { kind: "created", expiresAt };
  }

  #commitConfirm(pubkey: string, printed: string, nonce: string): TicketResult {
    const row = this.#load();
    if (!row) return { v: protocol.version, error: "ticket_not_found" };
    if (!this.#hasNonce("confirm", nonce)) return { v: protocol.version, error: "unauthorized" };
    const now = Date.now();
    if ((row.state === "open" || row.state === "bound") && now >= Number(row.expires_at)) {
      this.#expire(now);
      this.#deleteNonce("confirm", nonce);
      return { v: protocol.version, error: "expired", state: "expired" };
    }
    if (row.state === "open") {
      const seed = encodeB64Url(randomBytes(protocol.nonce_bytes));
      this.ctx.storage.sql.exec(
        `UPDATE ticket
         SET state = ?, bound_pubkey = ?, bound_fingerprint = ?, op = 0, seed_nonce = ?
         WHERE id = 1 AND state = ?`,
        "bound",
        pubkey,
        printed,
        seed,
        "open",
      );
      const written = this.#load();
      if (!written || written.state !== "bound" || written.bound_pubkey !== pubkey) {
        return { v: protocol.version, error: "ticket_bound", state: "bound" };
      }
      this.#deleteNonce("confirm", nonce);
      return {
        v: protocol.version,
        state: "bound",
        expires_at: Number(written.expires_at),
        fingerprint: written.bound_fingerprint ?? undefined,
        hint: this.#hint(written),
      };
    }
    if (row.state === "bound" && row.bound_pubkey === pubkey) {
      if (!row.seed_nonce) {
        const seed = encodeB64Url(randomBytes(protocol.nonce_bytes));
        this.ctx.storage.sql.exec("UPDATE ticket SET seed_nonce = ? WHERE id = 1 AND state = ?", seed, "bound");
      }
      this.#deleteNonce("confirm", nonce);
      const written = this.#load();
      if (!written) return { v: protocol.version, error: "ticket_not_found" };
      return {
        v: protocol.version,
        state: "bound",
        expires_at: Number(written.expires_at),
        fingerprint: written.bound_fingerprint ?? undefined,
        hint: this.#hint(written),
      };
    }
    if (row.state === "bound") {
      this.#deleteNonce("confirm", nonce);
      return {
        v: protocol.version,
        error: "ticket_bound",
        state: "bound",
        expires_at: Number(row.expires_at),
        fingerprint: row.bound_fingerprint ?? undefined,
      };
    }
    const terminal = terminalError(row.state);
    return { v: protocol.version, error: terminal ?? "conflict", state: this.#state(row.state) };
  }

  #commitRead(pubkey: string, nonce: string, counter: number): TicketResult {
    const row = this.#load();
    if (!row || row.op_nonce !== nonce) return { v: protocol.version, error: "unauthorized" };
    if (row.bound_pubkey !== pubkey) return { v: protocol.version, error: "forbidden" };
    if (row.state === "open") return { v: protocol.version, error: "ticket_not_bound", state: "open" };
    if (row.state !== "bound") {
      return { v: protocol.version, error: "payload_gone", state: this.#state(row.state) };
    }
    if (Number(row.op) !== counter) return { v: protocol.version, error: "conflict" };
    this.ctx.storage.sql.exec(
      "UPDATE ticket SET op = ?, op_nonce = NULL WHERE id = 1 AND state = ? AND op = ? AND op_nonce = ?",
      Number(row.op) + 1,
      "bound",
      Number(row.op),
      nonce,
    );
    const written = this.#load();
    if (!written || Number(written.op) !== Number(row.op) + 1) {
      return { v: protocol.version, error: "unauthorized" };
    }
    return {
      v: protocol.version,
      state: "bound",
      expires_at: Number(written.expires_at),
      envelope: row.envelope ?? undefined,
    };
  }

  #commitAck(pubkey: string, nonce: string, counter: number): TicketResult {
    const row = this.#load();
    if (!row || row.op_nonce !== nonce) return { v: protocol.version, error: "unauthorized" };
    if (row.bound_pubkey !== pubkey) return { v: protocol.version, error: "forbidden" };
    const now = Date.now();
    if ((row.state === "open" || row.state === "bound") && now >= Number(row.expires_at)) {
      this.#expire(now);
      return { v: protocol.version, error: "expired", state: "expired" };
    }
    if (row.state === "open") return { v: protocol.version, error: "ticket_not_bound", state: "open" };
    if (row.state === "consumed") {
      const op = Number(row.op);
      if (counter !== op && counter !== op - 1) return { v: protocol.version, error: "conflict" };
      this.ctx.storage.sql.exec("UPDATE ticket SET op_nonce = NULL WHERE id = 1 AND state = ?", "consumed");
      return { v: protocol.version, state: "consumed" };
    }
    if (row.state !== "bound") {
      return { v: protocol.version, error: terminalError(row.state) ?? "payload_gone", state: this.#state(row.state) };
    }
    if (Number(row.op) !== counter) return { v: protocol.version, error: "conflict" };
    const terminalAt = now;
    this.ctx.storage.sql.exec(
      `UPDATE ticket
       SET state = ?, terminal_at = ?, envelope = NULL, seed_nonce = NULL, op_nonce = NULL, op = ?
       WHERE id = 1 AND state = ? AND op = ? AND op_nonce = ?`,
      "consumed",
      terminalAt,
      Number(row.op) + 1,
      "bound",
      Number(row.op),
      nonce,
    );
    this.ctx.storage.sql.exec("DELETE FROM pending_nonce");
    const written = this.#load();
    if (!written || written.state !== "consumed") return { v: protocol.version, error: "unauthorized" };
    return { v: protocol.version, state: "consumed" };
  }

  #commitCancel(nonce: string): TicketResult {
    const row = this.#load();
    if (!row) return { v: protocol.version, error: "ticket_not_found" };
    if (!this.#hasNonce("cancel", nonce)) return { v: protocol.version, error: "unauthorized" };
    const terminal = terminalError(row.state);
    if (terminal) {
      this.#deleteNonce("cancel", nonce);
      return { v: protocol.version, error: terminal, state: this.#state(row.state) };
    }
    const now = Date.now();
    this.ctx.storage.sql.exec(
      `UPDATE ticket
       SET state = ?, terminal_at = ?, envelope = NULL, seed_nonce = NULL, op_nonce = NULL
       WHERE id = 1 AND (state = ? OR state = ?)`,
      "cancelled",
      now,
      "open",
      "bound",
    );
    this.ctx.storage.sql.exec("DELETE FROM pending_nonce");
    const written = this.#load();
    return { v: protocol.version, state: "cancelled", expires_at: written ? Number(written.expires_at) : undefined };
  }

  #commitRedeem(pubkey: string, seed: string): TicketResult {
    const row = this.#load();
    if (!row || row.seed_nonce !== seed) return { v: protocol.version, error: "unauthorized" };
    if (row.state !== "bound") return { v: protocol.version, error: "ticket_not_bound", state: this.#state(row.state) };
    if (row.bound_pubkey !== pubkey) return { v: protocol.version, error: "forbidden" };
    const next = encodeB64Url(randomBytes(protocol.nonce_bytes));
    this.ctx.storage.sql.exec(
      "UPDATE ticket SET seed_nonce = NULL, op_nonce = ? WHERE id = 1 AND state = ? AND seed_nonce = ?",
      next,
      "bound",
      seed,
    );
    const written = this.#load();
    if (!written || written.op_nonce !== next) return { v: protocol.version, error: "unauthorized" };
    return { v: protocol.version, nonce: next, state: "bound" };
  }

  #issueOpNonce(row: TicketRow): TicketResult {
    if (row.state === "open" || (row.state === "bound" && row.seed_nonce)) {
      return { v: protocol.version, error: row.state === "open" ? "ticket_not_bound" : "unauthorized" };
    }
    if (row.op_nonce) return { v: protocol.version, nonce: row.op_nonce };
    const next = encodeB64Url(randomBytes(protocol.nonce_bytes));
    this.ctx.storage.sql.exec(
      "UPDATE ticket SET op_nonce = ? WHERE id = 1 AND op_nonce IS NULL",
      next,
    );
    const written = this.#load();
    if (!written?.op_nonce) return { v: protocol.version, error: "unauthorized" };
    return { v: protocol.version, nonce: written.op_nonce };
  }

  #nonceValue(purpose: string): string | null {
    const rows = this.ctx.storage.sql
      .exec<{ value: string }>(
        "SELECT value FROM pending_nonce WHERE purpose = ? ORDER BY id LIMIT 1",
        purpose,
      )
      .toArray();
    return rows[0]?.value ?? null;
  }

  #expire(now: number): void {
    this.ctx.storage.sql.exec(
      `UPDATE ticket
       SET state = ?, terminal_at = ?, envelope = NULL, seed_nonce = NULL, op_nonce = NULL
       WHERE id = 1 AND (state = ? OR state = ?)`,
      "expired",
      now,
      "open",
      "bound",
    );
    this.ctx.storage.sql.exec("DELETE FROM pending_nonce");
  }

  #addConfirmNonce(value: string): void {
    const rows = this.ctx.storage.sql
      .exec<{ id: number }>("SELECT id FROM pending_nonce WHERE purpose = 'confirm' ORDER BY id")
      .toArray();
    const extra = rows.length - (protocol.confirm_nonce_cap - 1);
    for (let i = 0; i < extra; i++) {
      const id = rows[i]?.id;
      if (id !== undefined) this.ctx.storage.sql.exec("DELETE FROM pending_nonce WHERE id = ?", id);
    }
    this.ctx.storage.sql.exec("INSERT INTO pending_nonce (purpose, value) VALUES ('confirm', ?)", value);
  }

  #hasNonce(purpose: string, value: string): boolean {
    const rows = this.ctx.storage.sql
      .exec<{ value: string }>("SELECT value FROM pending_nonce WHERE purpose = ? AND value = ?", purpose, value)
      .toArray();
    return rows.length > 0;
  }

  #deleteNonce(purpose: string, value: string): void {
    this.ctx.storage.sql.exec("DELETE FROM pending_nonce WHERE purpose = ? AND value = ?", purpose, value);
  }

  #hint(row: TicketRow): Hint | undefined {
    if (!row.seed_nonce || (row.state !== "bound" && row.state !== "expired" && row.state !== "cancelled")) {
      return undefined;
    }
    if (row.state !== "bound" && row.state !== "expired" && row.state !== "cancelled") return undefined;
    const state = row.state === "bound" || row.state === "expired" || row.state === "cancelled" ? row.state : null;
    if (!state) return undefined;
    return {
      v: protocol.version,
      state,
      ticket_hash: row.ticket_hash,
      seed_nonce: row.seed_nonce,
      expires_at: Number(row.expires_at),
    };
  }

  #state(value: string): TicketState {
    if ((protocol.states as readonly string[]).includes(value)) return value as TicketState;
    return "open";
  }

  #load(): TicketRow | null {
    const rows = this.ctx.storage.sql
      .exec(
        `SELECT state, created_at, expires_at, terminal_at, bound_pubkey, bound_fingerprint, op,
                envelope_sha256, issuer_hash, ticket_hash, seed_nonce, op_nonce, envelope
         FROM ticket WHERE id = 1`,
      )
      .toArray() as unknown as TicketRow[];
    return rows[0] ?? null;
  }
}
