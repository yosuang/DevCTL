import { env, runInDurableObject } from "cloudflare:test";
import { expect, it } from "vitest";
import { encodeB64Url, encodeHex, sha256 } from "../src/bytes";
import { protocol } from "../src/protocol";
import { admit, shardObjectName, sourceObjectName, windowId } from "../src/gate";
import {
  CIPHERTEXT,
  PASSPHRASE,
  SHARE_URI,
  dumpTicket,
  exampleBytes,
  exampleEnvelope,
} from "./support";

it("the fourth admit is rate limited and stores no ciphertext", async () => {
  const source = "192.0.2.250";
  for (let i = 0; i < 3; i++) {
    const granted = await admit(env, source);
    expect("id" in granted).toBe(true);
  }
  expect(await admit(env, source)).toEqual({ error: "rate_limited" });
  const shard = await runInDurableObject(env.GATE.getByName(await shardObjectName(source)), async (_instance, state) => {
    const rows = state.storage.sql.exec<{ count: number }>("SELECT count FROM counter WHERE id = 1").toArray();
    const columns = state.storage.sql
      .exec<{ name: string }>("PRAGMA table_info(counter)")
      .toArray()
      .map((column) => column.name);
    return { count: rows[0] ? Number(rows[0].count) : 0, columns };
  });
  expect(shard.count).toBe(3);
  expect(shard.columns).not.toContain("envelope");
  const stored = await runInDurableObject(
    env.GATE.getByName(await sourceObjectName(source)),
    async (_instance, state) => {
      const columns = state.storage.sql
        .exec<{ name: string }>("PRAGMA table_info(grant_row)")
        .toArray()
        .map((column) => column.name);
      const rows = state.storage.sql.exec("SELECT * FROM grant_row").toArray();
      return { columns, text: JSON.stringify(rows) };
    },
  );
  expect(stored.columns).toEqual(["id", "expires_at", "ticket_hash", "window"]);
  expect(stored.text).not.toContain(CIPHERTEXT);
  expect(stored.text).not.toContain(PASSPHRASE);
  expect(stored.text).not.toContain(SHARE_URI);
  expect(stored.text).not.toContain("argon2id");
});

it("one grant cannot bind a second ticket", async () => {
  const source = "192.0.2.251";
  const name = await sourceObjectName(source);
  const gate = env.GATE.getByName(name);
  const grant = await gate.tryAdmit(Date.now());
  expect(grant).not.toBeNull();
  if (!grant) throw new Error("grant");
  const first = encodeHex(await sha256(exampleBytes("grant1")));
  const second = encodeHex(await sha256(exampleBytes("grant2")));
  expect(await gate.consume(grant.id, first)).toBe(true);
  expect(await gate.consume(grant.id, second)).toBe(false);
  expect(await gate.consume(grant.id, first)).toBe(true);

  const secret = exampleBytes("gtick2");
  const ticketName = encodeHex(await sha256(secret));
  const created = await env.TICKET.getByName(ticketName).create({
    ticket: encodeB64Url(secret),
    issuer_capability: encodeB64Url(exampleBytes("gtick2i")),
    envelope: exampleEnvelope(),
    grant_id: grant.id,
    grant_source: name,
  });
  expect(created.error).toBe("unauthorized");
  expect((await dumpTicket(ticketName)).state).toBeNull();
  expect((await dumpTicket(ticketName)).alarm).toBeNull();
});

it("a refund from the previous window does not admit above the shard cap", async () => {
  const cap = protocol.limits.shard_admits_per_window;
  const previous = windowId(Date.now()) - 1;
  const shard = env.GATE.getByName("shard:refund-window");
  await runInDurableObject(shard, async (_instance, state) => {
    state.storage.sql.exec("INSERT INTO counter (id, window, count) VALUES (1, ?, ?)", previous, cap);
  });
  expect(await shard.debit()).toBe(true);
  expect(await shard.refund(previous)).toBe(true);
  let admitted = 1;
  for (let i = 0; i < cap; i++) {
    if (await shard.debit()) admitted += 1;
  }
  expect(admitted).toBe(cap);
  const count = await runInDurableObject(shard, async (_instance, state) => {
    const rows = state.storage.sql
      .exec<{ count: number; window: number }>("SELECT count, window FROM counter WHERE id = 1")
      .toArray();
    return { count: rows[0] ? Number(rows[0].count) : 0, window: rows[0] ? Number(rows[0].window) : 0 };
  });
  expect(count.count).toBe(cap);
  expect(count.window).toBe(previous + 1);

  const same = env.GATE.getByName("shard:refund-same");
  const current = windowId(Date.now());
  await runInDurableObject(same, async (_instance, state) => {
    state.storage.sql.exec("INSERT INTO counter (id, window, count) VALUES (1, ?, 1)", current);
  });
  expect(await same.refund(current)).toBe(true);
  const refunded = await runInDurableObject(same, async (_instance, state) => {
    const rows = state.storage.sql.exec<{ count: number }>("SELECT count FROM counter WHERE id = 1").toArray();
    return rows[0] ? Number(rows[0].count) : 0;
  });
  expect(refunded).toBe(0);
});
