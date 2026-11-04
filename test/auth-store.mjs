// Connection store behaviour. Uses the built output in dist/.
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  AuthStore,
  hashToken,
  REFRESH_GRACE_MS,
  IDLE_EXPIRY_MS,
} from "../dist/auth/store.js";

const DAY = 24 * 60 * 60 * 1000;
let failed = 0;
const dirs = [];

async function tmp() {
  const d = await fs.mkdtemp(path.join(os.tmpdir(), "auth-store-"));
  dirs.push(d);
  return d;
}

async function check(name, fn) {
  try {
    await fn();
    console.log(`ok - ${name}`);
  } catch (err) {
    failed++;
    console.error(`FAIL - ${name}\n${err.stack}`);
  }
}

function conn(over = {}) {
  return {
    id: "c1",
    clientId: "client-a",
    person: { id: "p1", name: "Alice" },
    upstream: { refresh_token: "ha-refresh" },
    refreshHash: hashToken("refresh-one"),
    lastUsedAt: 1000,
    ...over,
  };
}

await check("a saved client survives reopening", async () => {
  const dir = await tmp();
  const a = await AuthStore.open(dir, () => 1000);
  await a.saveClient({ client_id: "client-a", redirect_uris: ["https://x.example/cb"] });
  const b = await AuthStore.open(dir, () => 1000);
  assert.equal(b.getClient("client-a")?.client_id, "client-a");
  assert.equal(b.getClient("nope"), undefined);
});

await check("putConnection replaces the same client and person and returns the old one", async () => {
  const dir = await tmp();
  const s = await AuthStore.open(dir, () => 1000);
  assert.equal(await s.putConnection(conn()), undefined);
  const old = await s.putConnection(conn({ id: "c2", refreshHash: hashToken("refresh-two") }));
  assert.equal(old?.id, "c1");
  assert.equal(s.findByRefresh("client-a", "refresh-one"), undefined);
  assert.equal(s.findByRefresh("client-a", "refresh-two")?.connection.id, "c2");
  // a different person or client is kept
  await s.putConnection(conn({ id: "c3", person: { id: "p2", name: "Bob" }, refreshHash: hashToken("r3") }));
  await s.putConnection(conn({ id: "c4", clientId: "client-b", refreshHash: hashToken("r4") }));
  assert.ok(s.findByRefresh("client-a", "refresh-two"));
  assert.ok(s.findByRefresh("client-a", "r3"));
  assert.ok(s.findByRefresh("client-b", "r4"));
  // a token only matches under its own client
  assert.equal(s.findByRefresh("client-b", "r3"), undefined);
});

await check("refresh tokens are stored hashed", async () => {
  const dir = await tmp();
  const s = await AuthStore.open(dir, () => 1000);
  await s.putConnection(conn());
  const raw = await fs.readFile(path.join(dir, "oauth.json"), "utf8");
  assert.ok(!raw.includes("refresh-one"));
  assert.ok(raw.includes(hashToken("refresh-one")));
  assert.match(hashToken("x"), /^[0-9a-f]{64}$/);
});

await check("findByRefresh matches the previous token only within 60 seconds of rotation", async () => {
  const dir = await tmp();
  let t = 1_000_000;
  const s = await AuthStore.open(dir, () => t);
  assert.equal(REFRESH_GRACE_MS, 60_000);
  await s.putConnection(conn({
    refreshHash: hashToken("new"),
    previousRefreshHash: hashToken("old"),
    rotatedAt: t,
  }));
  const current = s.findByRefresh("client-a", "new");
  assert.equal(current?.stale, false);
  t += 60_000;
  const stale = s.findByRefresh("client-a", "old");
  assert.equal(stale?.stale, true);
  t += 1;
  assert.equal(s.findByRefresh("client-a", "old"), undefined);
});

await check("expired is true after 90 days unused and false at 89", async () => {
  const dir = await tmp();
  let t = 0;
  const s = await AuthStore.open(dir, () => t);
  assert.equal(IDLE_EXPIRY_MS, 90 * DAY);
  const c = conn({ lastUsedAt: 0 });
  t = 89 * DAY;
  assert.equal(s.expired(c), false);
  t = 90 * DAY;
  assert.equal(s.expired(c), false);
  t = 90 * DAY + 1;
  assert.equal(s.expired(c), true);
});

await check("a corrupt oauth.json refuses to open with the file name in the error", async () => {
  const dir = await tmp();
  await fs.writeFile(path.join(dir, "oauth.json"), "{not json");
  await assert.rejects(AuthStore.open(dir), (e) => {
    assert.match(e.message, /oauth\.json/);
    return true;
  });
});

await check("a missing oauth.json starts empty and a wrong shape is refused", async () => {
  const dir = await tmp();
  const s = await AuthStore.open(path.join(dir, "sub", "dir"), () => 0);
  assert.equal(s.getClient("x"), undefined);
  const bad = await tmp();
  await fs.writeFile(path.join(bad, "oauth.json"), JSON.stringify({ clients: [] }));
  await assert.rejects(AuthStore.open(bad), /oauth\.json/);
});

await check("an unwritable data dir refuses to open naming the directory", async () => {
  const dir = await tmp();
  const file = path.join(dir, "afile");
  await fs.writeFile(file, "x");
  await assert.rejects(AuthStore.open(path.join(file, "data")), (e) => {
    assert.match(e.message, /afile/);
    return true;
  });
});

await check("keys from outside never hit inherited members", async () => {
  const dir = await tmp();
  const s = await AuthStore.open(dir, () => 1000);
  assert.equal(s.getClient("constructor"), undefined);
  assert.equal(s.getClient("__proto__"), undefined);
  assert.equal(s.getClient("toString"), undefined);
  assert.equal(await s.removeConnection("toString"), undefined);
  assert.equal(await s.removeConnection("__proto__"), undefined);
  await s.saveClient({ client_id: "__proto__", redirect_uris: ["https://x.example/cb"] });
  assert.equal(s.getClient("__proto__")?.client_id, "__proto__");
  assert.equal(s.getClient("other"), undefined);
  assert.equal(({}).redirect_uris, undefined);
  const again = await AuthStore.open(dir, () => 1000);
  assert.equal(again.getClient("__proto__")?.client_id, "__proto__");
  assert.equal(again.getClient("constructor"), undefined);
});

await check("updateConnection and removeConnection persist", async () => {
  const dir = await tmp();
  const s = await AuthStore.open(dir, () => 1000);
  await s.putConnection(conn());
  await s.updateConnection(conn({ refreshHash: hashToken("rotated"), lastUsedAt: 5000 }));
  const again = await AuthStore.open(dir, () => 1000);
  assert.equal(again.findByRefresh("client-a", "rotated")?.connection.lastUsedAt, 5000);
  const removed = await again.removeConnection("c1");
  assert.equal(removed?.id, "c1");
  assert.equal(await again.removeConnection("c1"), undefined);
  const third = await AuthStore.open(dir, () => 1000);
  assert.equal(third.findByRefresh("client-a", "rotated"), undefined);
});

await check("quick concurrent saves do not interleave", async () => {
  const dir = await tmp();
  const s = await AuthStore.open(dir, () => 1000);
  await Promise.all(
    Array.from({ length: 20 }, (_, i) =>
      s.saveClient({ client_id: `c${i}`, redirect_uris: ["https://x.example/cb"] })),
  );
  const again = await AuthStore.open(dir, () => 1000);
  for (let i = 0; i < 20; i++) assert.ok(again.getClient(`c${i}`));
});

for (const d of dirs) await fs.rm(d, { recursive: true, force: true });
if (failed) {
  console.error(`${failed} check(s) failed`);
  process.exit(1);
}
console.log("auth-store: all checks passed");
