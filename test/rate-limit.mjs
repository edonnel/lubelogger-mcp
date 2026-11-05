// The failed sign-in limiter, driven by an injected clock so nothing sleeps.
import assert from "node:assert/strict";
import { addressKey, FailureLimiter, MAX_FAILURES, MAX_KEYS, WINDOW_MS } from "../dist/auth/rate-limit.js";

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

// one attempt as the sign-in form makes it: checked first, and recorded as a failure only when let in
function attempt(limiter, keys) {
  if (limiter.lockedFor(keys) > 0) return false;
  limiter.fail(keys);
  return true;
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

await check("memory stays bounded: attempts made one after another hold at most MAX_KEYS keys", () => {
  const { clock, limiter } = make();
  for (let i = 0; i < 100_000; i++) attempt(limiter, [`addr:${i}`]);
  assert.ok(limiter.size() <= MAX_KEYS);
  clock.t += WINDOW_MS + 1;
  assert.ok(attempt(limiter, ["addr:last"]));
  assert.equal(limiter.size(), 1);
});

await check("a flood of distinct live keys stays within MAX_KEYS, keeps earlier lockouts, and adds no new key", () => {
  const { limiter } = make();
  for (let i = 0; i < MAX_FAILURES; i++) limiter.fail(["user:locked"]);
  for (let i = 0; i < MAX_KEYS + 10_000; i++) attempt(limiter, [`addr:${i}`]);
  assert.ok(limiter.size() <= MAX_KEYS);
  assert.ok(limiter.lockedFor(["user:locked"]) > 0);
  assert.equal(limiter.held(`addr:${MAX_KEYS + 9_999}`), 0, "the last key of the flood was not added");
});

await check("when every key is locked, a new key is refused and so never tracked", () => {
  const { limiter } = make();
  for (let i = 0; i < MAX_KEYS; i++) for (let j = 0; j < MAX_FAILURES; j++) limiter.fail([`k${i}`]);
  assert.equal(limiter.size(), MAX_KEYS);
  assert.equal(attempt(limiter, ["new"]), false);
  assert.equal(limiter.size(), MAX_KEYS);
  assert.equal(limiter.held("new"), 0);
  assert.ok(limiter.lockedFor(["new"]) > 0);
  assert.ok(limiter.lockedFor(["k0"]) > 0);
});

await check("a flood of keys with one live failure each never resets a held key's count", () => {
  const { clock, limiter } = make();
  for (let i = 0; i < MAX_FAILURES - 1; i++) limiter.fail(["user:alice"]);
  clock.t += 1000;
  for (let i = 0; i < MAX_KEYS + 10_000; i++) attempt(limiter, [`addr:${i}`]);
  assert.equal(limiter.size(), MAX_KEYS);
  assert.equal(limiter.failureCount("user:alice"), MAX_FAILURES - 1, "alice's four failures survive the flood");
  assert.ok(attempt(limiter, ["user:alice"]));
  assert.ok(limiter.lockedFor(["user:alice"]) > 0, "the fifth failure locks alice");
});

await check("while the map is full, a key not held is refused, and allowed again after the window", () => {
  const { clock, limiter } = make();
  for (let i = 0; i < MAX_KEYS + 10; i++) attempt(limiter, [`addr:${i}`]);
  assert.equal(limiter.size(), MAX_KEYS);
  // the flood came in at one instant, before any prune, so the wait is a whole window
  assert.equal(limiter.lockedFor(["addr:brand-new"]), WINDOW_MS);
  assert.ok(limiter.lockedFor(["addr:203.0.113.9", "user:bob"]) > 0, "a pair with any key not held is refused");
  // a held key with one failure is not locked
  assert.equal(limiter.lockedFor(["addr:0"]), 0);
  // a minute on, a prune has measured the oldest failure, so the wait counts down from it
  clock.t += 60_000;
  assert.equal(limiter.lockedFor(["addr:brand-new"]), WINDOW_MS - 60_000);
  clock.t += WINDOW_MS - 60_000;
  assert.equal(limiter.lockedFor(["addr:brand-new"]), 0);
  assert.equal(limiter.size(), 0, "checking pruned the expired keys");
  limiter.fail(["addr:brand-new"]);
  assert.equal(limiter.held("addr:brand-new"), 1);
});

await check("an attempt let in while there was room is counted even if the map fills before it fails", () => {
  const { clock, limiter } = make();
  for (let i = 0; i < MAX_KEYS - 1; i++) limiter.fail([`addr:${i}`]);
  // five guesses at bob and one at carol are let in while there is still room: all six are in flight at once
  for (let i = 0; i < MAX_FAILURES; i++) assert.equal(limiter.lockedFor(["user:bob"]), 0, "bob is let in");
  assert.equal(limiter.lockedFor(["user:carol"]), 0, "carol is let in");
  // other failures fill the map while those are being checked
  limiter.fail(["addr:filler"]);
  assert.equal(limiter.size(), MAX_KEYS);
  limiter.fail(["user:bob"]);
  assert.equal(limiter.failureCount("user:bob"), 1, "the first admitted failure is recorded");
  for (let i = 1; i < MAX_FAILURES; i++) limiter.fail(["user:bob"]);
  limiter.fail(["user:carol"]);
  assert.ok(limiter.lockedFor(["user:bob"]) > 0, "five admitted failures lock bob");
  assert.equal(limiter.failureCount("user:carol"), 1);
  // the map goes past MAX_KEYS only by the keys that were let in: bob and carol
  assert.equal(limiter.size(), MAX_KEYS + 2);
  assert.ok(limiter.lockedFor(["user:dave"]) > 0, "a key not held is still refused past MAX_KEYS");
  // once the failures expire, pruning brings the map back down
  clock.t += WINDOW_MS;
  assert.equal(limiter.lockedFor(["user:dave"]), 0);
  assert.equal(limiter.size(), 0);
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

await check("failureCount() counts a key's failures inside the window and changes nothing", () => {
  const { clock, limiter } = make();
  assert.equal(limiter.failureCount("user:dave"), 0);
  limiter.fail(["user:dave"]);
  clock.t += 1000;
  limiter.fail(["user:dave"]);
  assert.equal(limiter.failureCount("user:dave"), 2);
  assert.equal(limiter.failureCount("user:" + "x".repeat(300)), 0);
  assert.equal(limiter.size(), 1, "reading a key does not add it");
  assert.equal(limiter.lockedFor(["user:dave"]), 0);
  clock.t += WINDOW_MS - 1000;
  assert.equal(limiter.failureCount("user:dave"), 1, "the first one has left the window");
  clock.t += 1000;
  assert.equal(limiter.failureCount("user:dave"), 0);
});

await check("addressKey() keys IPv6 by its /64, maps IPv4-mapped addresses to IPv4, and keeps IPv4", () => {
  const net = "addr:2001:db8:1:2::/64";
  assert.equal(addressKey("2001:0db8:0001:0002:0003:0004:0005:0006"), net, "full form");
  assert.equal(addressKey("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), net, "another address in the same /64");
  assert.equal(addressKey("2001:DB8:1:2::9"), net, "compressed, upper case");
  assert.equal(addressKey("2001:db8:1:2::"), net);
  assert.equal(addressKey("2001:db8::1"), "addr:2001:db8:0:0::/64", "compression inside the prefix");
  assert.equal(addressKey("fe80::1%eth0"), "addr:fe80:0:0:0::/64", "a zone is ignored");
  assert.notEqual(addressKey("2001:db8:1:3::1"), net, "the next /64 is another key");
  assert.equal(addressKey("::ffff:198.51.100.7"), "addr:198.51.100.7");
  assert.equal(addressKey("::FFFF:c633:6407"), "addr:198.51.100.7", "mapped, in hex");
  assert.equal(addressKey("198.51.100.7"), "addr:198.51.100.7");
  assert.equal(addressKey(""), "addr:unknown");
  assert.equal(addressKey(undefined), "addr:unknown");
});

if (failed) {
  process.stderr.write(`${failed} check(s) failed\n`);
  process.exit(1);
}
