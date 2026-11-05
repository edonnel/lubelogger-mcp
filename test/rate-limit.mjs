// The failed sign-in limiter, driven by an injected clock so nothing sleeps.
import assert from "node:assert/strict";
import { FailureLimiter, MAX_FAILURES, MAX_KEYS, WINDOW_MS } from "../dist/auth/rate-limit.js";

let failed = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log(`ok - ${name}`);
  } catch (err) {
    failed++;
    process.stderr.write(`FAIL - ${name}\n${err.stack}\n`);
  }
}

function make() {
  const clock = { t: 1_000_000 };
  return { clock, limiter: new FailureLimiter(() => clock.t) };
}

await check("five failures lock the key for 15 minutes; it is free again after", () => {
  const { clock, limiter } = make();
  for (let i = 0; i < MAX_FAILURES - 1; i++) {
    limiter.fail(["user:alice"]);
    clock.t += 1000;
  }
  assert.equal(limiter.lockedFor(["user:alice"]), 0);
  limiter.fail(["user:alice"]);
  assert.ok(limiter.lockedFor(["user:alice"]) > 0);
  // the oldest counted failure was 4 seconds ago
  assert.equal(limiter.lockedFor(["user:alice"]), WINDOW_MS - 4000);
  clock.t += WINDOW_MS - 4000;
  assert.equal(limiter.lockedFor(["user:alice"]), 0);
});

await check("failures older than 15 minutes don't count", () => {
  const { clock, limiter } = make();
  for (let i = 0; i < MAX_FAILURES - 1; i++) limiter.fail(["user:bob"]);
  clock.t += WINDOW_MS + 1;
  limiter.fail(["user:bob"]);
  assert.equal(limiter.lockedFor(["user:bob"]), 0);
  // four fresh failures plus the one above make five within the window
  for (let i = 0; i < MAX_FAILURES - 1; i++) limiter.fail(["user:bob"]);
  assert.ok(limiter.lockedFor(["user:bob"]) > 0);
});

await check("a locked username locks every address that tries it, and a locked address locks every username", () => {
  const { limiter } = make();
  for (let i = 0; i < MAX_FAILURES; i++) limiter.fail(["user:x"]);
  assert.ok(limiter.lockedFor(["addr:a", "user:x"]) > 0);
  assert.ok(limiter.lockedFor(["addr:b", "user:x"]) > 0);
  assert.equal(limiter.lockedFor(["addr:a", "user:y"]), 0);
  for (let i = 0; i < MAX_FAILURES; i++) limiter.fail(["addr:a"]);
  assert.ok(limiter.lockedFor(["addr:a", "user:y"]) > 0);
});

await check("memory stays bounded", () => {
  const { clock, limiter } = make();
  for (let i = 0; i < 100_000; i++) limiter.fail([`addr:${i}`]);
  assert.ok(limiter.size() <= MAX_KEYS);
  clock.t += WINDOW_MS + 1;
  limiter.fail(["addr:last"]);
  assert.equal(limiter.size(), 1);
});

await check("a flood of distinct live keys stays within MAX_KEYS and keeps earlier lockouts", () => {
  const { limiter } = make();
  for (let i = 0; i < MAX_FAILURES; i++) limiter.fail(["user:locked"]);
  for (let i = 0; i < MAX_KEYS + 10_000; i++) limiter.fail([`addr:${i}`]);
  assert.ok(limiter.size() <= MAX_KEYS);
  assert.ok(limiter.lockedFor(["user:locked"]) > 0);
});

await check("when every key is locked, a new key is not tracked", () => {
  const { limiter } = make();
  for (let i = 0; i < MAX_KEYS; i++) for (let j = 0; j < MAX_FAILURES; j++) limiter.fail([`k${i}`]);
  assert.equal(limiter.size(), MAX_KEYS);
  limiter.fail(["new"]);
  assert.equal(limiter.size(), MAX_KEYS);
  assert.equal(limiter.held("new"), 0);
  assert.ok(limiter.lockedFor(["k0"]) > 0);
});

await check("a key that fails 100 times holds at most MAX_FAILURES timestamps and stays locked", () => {
  const { clock, limiter } = make();
  for (let i = 0; i < 100; i++) {
    limiter.fail(["user:spam"]);
    clock.t += 1000;
  }
  assert.equal(limiter.held("user:spam"), MAX_FAILURES);
  assert.ok(limiter.lockedFor(["user:spam"]) > 0);
});

await check("keys that differ only after character 200 are the same key", () => {
  const { limiter } = make();
  const base = "u".repeat(200);
  for (let i = 0; i < MAX_FAILURES; i++) limiter.fail([base + i]);
  assert.equal(limiter.size(), 1);
  assert.ok(limiter.lockedFor([base + "other"]) > 0);
});

if (failed) {
  process.stderr.write(`${failed} check(s) failed\n`);
  process.exit(1);
}
