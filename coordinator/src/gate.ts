import { DurableObject } from "cloudflare:workers";
import { encodeB64Url, encodeHex, randomBytes, sha256, utf8 } from "./bytes";
import { protocol } from "./protocol";

export interface Grant {
  id: string;
  source_name: string;
  expires_at: number;
}

export interface RateLimited {
  error: "rate_limited";
}

export function windowId(now: number): number {
  return Math.floor(now / protocol.limits.window_ms);
}

export async function sourceObjectName(source: string): Promise<string> {
  return `source:${encodeHex(await sha256(utf8(source)))}`;
}

export async function shardObjectName(source: string): Promise<string> {
  const hash = await sha256(utf8(source));
  const index = (hash[0] ?? 0) % protocol.limits.shard_count;
  return `shard:${index}`;
}

export function sourceKey(request: Request): string {
  const header = request.headers.get("CF-Connecting-IP");
  if (!header) return protocol.local_source;
  return header;
}

export async function admit(env: Env, source: string): Promise<Grant | RateLimited> {
  const name = await sourceObjectName(source);
  const shard = env.GATE.getByName(await shardObjectName(source));
  const sourceDo = env.GATE.getByName(name);
  let released: number[] = [];
  try {
    released = await sourceDo.releaseExpired(Date.now());
  } catch {
    return { error: "rate_limited" };
  }
  for (const window of released) {
    try {
      await shard.refund(window);
    } catch {
      // A missed refund over-counts. Creation still fails closed below.
    }
  }
  let debited = false;
  const debitedWindow = windowId(Date.now());
  try {
    debited = await shard.debit();
  } catch {
    return { error: "rate_limited" };
  }
  if (!debited) return { error: "rate_limited" };
  try {
    const grant = await sourceDo.tryAdmit(Date.now());
    if (!grant) {
      try {
        await shard.refund(debitedWindow);
      } catch {
        // Over-count, still deny.
      }
      return { error: "rate_limited" };
    }
    return { id: grant.id, source_name: name, expires_at: grant.expires_at };
  } catch {
    try {
      await shard.refund(debitedWindow);
    } catch {
      // Over-count, still deny.
    }
    return { error: "rate_limited" };
  }
}

export class CreateGate extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    ctx.blockConcurrencyWhile(async () => {
      this.ctx.storage.sql.exec(
        `CREATE TABLE IF NOT EXISTS counter (
          id INTEGER PRIMARY KEY CHECK (id = 1),
          window INTEGER NOT NULL,
          count INTEGER NOT NULL
        )`,
      );
      this.ctx.storage.sql.exec(
        `CREATE TABLE IF NOT EXISTS grant_row (
          id TEXT PRIMARY KEY,
          expires_at INTEGER NOT NULL,
          ticket_hash TEXT,
          window INTEGER NOT NULL
        )`,
      );
    });
  }

  async debit(): Promise<boolean> {
    const now = Date.now();
    const window = windowId(now);
    const rows = this.ctx.storage.sql
      .exec<{ window: number; count: number }>("SELECT window, count FROM counter WHERE id = 1")
      .toArray();
    const current = rows[0];
    const count = current && Number(current.window) === window ? Number(current.count) : 0;
    if (count >= protocol.limits.shard_admits_per_window) return false;
    if (!current) {
      this.ctx.storage.sql.exec("INSERT INTO counter (id, window, count) VALUES (1, ?, ?)", window, 1);
    } else {
      this.ctx.storage.sql.exec("UPDATE counter SET window = ?, count = ? WHERE id = 1", window, count + 1);
    }
    return true;
  }

  async refund(window: number): Promise<boolean> {
    try {
      const rows = this.ctx.storage.sql
        .exec<{ window: number; count: number }>("SELECT window, count FROM counter WHERE id = 1")
        .toArray();
      const current = rows[0];
      if (!current || Number(current.window) !== window) return true;
      const count = Number(current.count);
      if (count <= 0) return true;
      this.ctx.storage.sql.exec(
        "UPDATE counter SET count = ? WHERE id = 1 AND window = ?",
        count - 1,
        window,
      );
      return true;
    } catch {
      return false;
    }
  }

  async releaseExpired(now: number): Promise<number[]> {
    const rows = this.ctx.storage.sql
      .exec<{ id: string; window: number }>(
        "SELECT id, window FROM grant_row WHERE ticket_hash IS NULL AND expires_at <= ?",
        now,
      )
      .toArray();
    for (const row of rows) {
      this.ctx.storage.sql.exec("DELETE FROM grant_row WHERE id = ?", row.id);
    }
    return rows.map((row) => Number(row.window));
  }

  async tryAdmit(now: number): Promise<{ id: string; expires_at: number } | null> {
    const window = windowId(now);
    const rows = this.ctx.storage.sql
      .exec<{ n: number }>(
        `SELECT COUNT(*) AS n FROM grant_row
         WHERE window = ? AND (ticket_hash IS NOT NULL OR expires_at > ?)`,
        window,
        now,
      )
      .toArray();
    const active = rows[0] ? Number(rows[0].n) : 0;
    if (active >= protocol.limits.source_admits_per_window) return null;
    const id = encodeB64Url(randomBytes(protocol.nonce_bytes));
    const expiresAt = now + protocol.limits.grant_ttl_ms;
    this.ctx.storage.sql.exec(
      "INSERT INTO grant_row (id, expires_at, ticket_hash, window) VALUES (?, ?, NULL, ?)",
      id,
      expiresAt,
      window,
    );
    return { id, expires_at: expiresAt };
  }

  async consume(grantId: string, ticketHash: string): Promise<boolean> {
    const now = Date.now();
    const rows = this.ctx.storage.sql
      .exec<{ expires_at: number; ticket_hash: string | null }>(
        "SELECT expires_at, ticket_hash FROM grant_row WHERE id = ?",
        grantId,
      )
      .toArray();
    const row = rows[0];
    if (!row) return false;
    if (row.ticket_hash === ticketHash) return true;
    if (row.ticket_hash) return false;
    if (Number(row.expires_at) <= now) {
      this.ctx.storage.sql.exec("DELETE FROM grant_row WHERE id = ? AND ticket_hash IS NULL", grantId);
      return false;
    }
    this.ctx.storage.sql.exec(
      "UPDATE grant_row SET ticket_hash = ? WHERE id = ? AND ticket_hash IS NULL",
      ticketHash,
      grantId,
    );
    const written = this.ctx.storage.sql
      .exec<{ ticket_hash: string | null }>("SELECT ticket_hash FROM grant_row WHERE id = ?", grantId)
      .toArray();
    return written[0]?.ticket_hash === ticketHash;
  }
}
