// The LubeLogger password and API key login methods against a mock LubeLogger on node:http.
// The mock implements /api/whoami the way LubeLogger 1.7.4 does: Basic or x-api-key, 401 for anything else,
// and with its login switched off, root "admin" for every request.
import assert from "node:assert/strict";
import http from "node:http";
import { LubeLoggerKeyLogin, LubeLoggerPasswordLogin } from "../dist/auth/lubelogger-login.js";

const SECRETS = ["pw-alice", "pw-bob", "key-alice"];
const LOGIN_OFF = /LubeLogger's own login is turned off/;
const UNAVAILABLE = "LubeLogger can't be reached right now. Try again shortly.";

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

// every message a result carried, and every error thrown, compared against the secrets at the end
const messages = [];
function note(result) {
  for (const k of ["invalid", "refused", "unavailable"]) if (typeof result[k] === "string") messages.push(result[k]);
  return result;
}
async function run(fn) {
  try {
    return note(await fn());
  } catch (err) {
    messages.push(err instanceof Error ? err.message : String(err));
    throw err;
  }
}

// ---------- the mock LubeLogger ----------
const mock = {
  users: new Map([
    ["alice", "pw-alice"],
    ["bob", "pw-bob"],
  ]),
  keys: new Map([["key-alice", "alice"]]),
  authOff: false,
  status: undefined,
  requests: [],
  reset() {
    this.keys = new Map([["key-alice", "alice"]]);
    this.authOff = false;
    this.status = undefined;
    this.requests = [];
  },
};

function whoamiUser(req) {
  const auth = req.headers.authorization;
  if (typeof auth === "string" && auth.startsWith("Basic ")) {
    // LubeLogger splits on ":", so a password holding one can never match
    const parts = Buffer.from(auth.slice(6), "base64").toString("utf8").split(":");
    if (parts.length === 2 && mock.users.get(parts[0]) === parts[1]) return parts[0];
    return undefined;
  }
  const key = req.headers["x-api-key"];
  if (typeof key === "string") return mock.keys.get(key);
  return undefined;
}

const server = http.createServer((req, res) => {
  mock.requests.push({ url: req.url, headers: req.headers });
  const send = (status, body) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(body === undefined ? "" : JSON.stringify(body));
  };
  if (mock.status) return send(mock.status, { message: "boom" });
  if (req.url !== "/api/whoami") return send(404);
  if (mock.authOff) return send(200, { username: "admin", emailAddress: "", isAdmin: "True", isRoot: "True" });
  const user = whoamiUser(req);
  if (!user) return send(401);
  send(200, { username: user, emailAddress: `${user}@example.com`, isAdmin: "False", isRoot: "False" });
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const URL_OK = `http://127.0.0.1:${server.address().port}`;

// a port nothing listens on
const closed = http.createServer();
await new Promise((r) => closed.listen(0, "127.0.0.1", r));
const URL_DOWN = `http://127.0.0.1:${closed.address().port}`;
await new Promise((r) => closed.close(r));

const password = (opts = {}) =>
  new LubeLoggerPasswordLogin({ lubeloggerUrl: URL_OK, allowedUsers: ["alice"], timeoutMs: 2000, ...opts });
const key = (opts = {}) => new LubeLoggerKeyLogin({ lubeloggerUrl: URL_OK, timeoutMs: 2000, ...opts });

// ---------- tests ----------
await check("password: an allowlisted user with the right password signs in", async () => {
  mock.reset();
  const m = password();
  assert.equal(m.form, "password");
  const r = await run(() => m.check({ username: "alice", password: "pw-alice" }));
  assert.deepEqual(r, { person: { id: "alice", name: "alice" }, upstream: { username: "alice" } });
  const basic = `Basic ${Buffer.from("alice:pw-alice").toString("base64")}`;
  assert.ok(mock.requests.some((q) => q.headers.authorization === basic));
  assert.ok(mock.requests.every((q) => q.headers["culture-invariant"] !== undefined));
});

await check("password: a wrong password is invalid; an unknown user is invalid with the same message", async () => {
  mock.reset();
  const m = password();
  const wrong = await run(() => m.check({ username: "alice", password: "pw-bob" }));
  const unknown = await run(() => m.check({ username: "carol", password: "pw-alice" }));
  assert.deepEqual(wrong, { invalid: "That username or password is wrong." });
  assert.deepEqual(unknown, wrong);
});

await check("password: a correct password for someone not allowlisted is refused", async () => {
  mock.reset();
  const r = await run(() => password().check({ username: "bob", password: "pw-bob" }));
  assert.deepEqual(r, { refused: "bob is not allowed to use LubeLogger MCP.", person: { id: "bob", name: "bob" } });
});

await check("password: a password containing a colon is invalid without a network call", async () => {
  mock.reset();
  const r = await run(() => password().check({ username: "alice", password: "pw:alice" }));
  assert.deepEqual(r, { invalid: "That username or password is wrong." });
  assert.equal(mock.requests.length, 0);
});

await check("password: empty fields are invalid without a network call", async () => {
  mock.reset();
  const m = password();
  for (const fields of [{}, { username: "alice" }, { password: "pw-alice" }, { username: "", password: "" }]) {
    const r = await run(() => m.check(fields));
    assert.deepEqual(r, { invalid: "That username or password is wrong." });
  }
  assert.equal(mock.requests.length, 0);
});

await check("key: a valid key signs in as its owner, and the upstream keeps the key", async () => {
  mock.reset();
  const m = key();
  assert.equal(m.form, "key");
  const r = await run(() => m.check({ apiKey: "key-alice" }));
  assert.deepEqual(r, { person: { id: "alice", name: "alice" }, upstream: { username: "alice", apiKey: "key-alice" } });
  assert.ok(mock.requests.some((q) => q.headers["x-api-key"] === "key-alice"));
});

await check("key: an unknown key is invalid", async () => {
  mock.reset();
  const m = key();
  assert.deepEqual(await run(() => m.check({ apiKey: "key-nobody" })), { invalid: "That API key is not valid." });
  mock.requests = [];
  assert.deepEqual(await run(() => m.check({})), { invalid: "That API key is not valid." });
  assert.equal(mock.requests.length, 0);
});

await check("LubeLogger with its login off refuses every password and key, at sign-in and on recheck", async () => {
  mock.reset();
  mock.authOff = true;
  const p = await run(() => password({ allowedUsers: ["alice", "admin"] }).check({ username: "alice", password: "pw-alice" }));
  assert.ok("refused" in p, JSON.stringify(p));
  assert.match(p.refused, LOGIN_OFF);
  const k = await run(() => key().check({ apiKey: "key-alice" }));
  assert.ok("refused" in k, JSON.stringify(k));
  assert.match(k.refused, LOGIN_OFF);
  assert.deepEqual(await key().recheck({ username: "alice", apiKey: "key-alice" }), { ok: false, reason: "refused" });
  // no credential was sent to a LubeLogger that would have accepted anything
  assert.ok(mock.requests.every((q) => q.headers.authorization === undefined && q.headers["x-api-key"] === undefined));
});

await check("a 500 or an unreachable LubeLogger is unavailable", async () => {
  mock.reset();
  mock.status = 500;
  const unavailable = { unavailable: UNAVAILABLE };
  assert.deepEqual(await run(() => password().check({ username: "alice", password: "pw-alice" })), unavailable);
  assert.deepEqual(await run(() => key().check({ apiKey: "key-alice" })), unavailable);
  assert.deepEqual(await key().recheck({ username: "alice", apiKey: "key-alice" }), { ok: false, reason: "unavailable" });

  const down = { lubeloggerUrl: URL_DOWN };
  assert.deepEqual(await run(() => password(down).check({ username: "alice", password: "pw-alice" })), unavailable);
  assert.deepEqual(await run(() => key(down).check({ apiKey: "key-alice" })), unavailable);
  assert.deepEqual(await key(down).recheck({ username: "alice", apiKey: "key-alice" }), { ok: false, reason: "unavailable" });
});

await check("password recheck follows the allowlist only, with no network call", async () => {
  mock.reset();
  assert.deepEqual(await password().recheck({ username: "alice" }), {
    ok: true,
    upstream: { username: "alice" },
    person: { id: "alice", name: "alice" },
  });
  assert.deepEqual(await password({ allowedUsers: ["bob"] }).recheck({ username: "alice" }), { ok: false, reason: "refused" });
  assert.deepEqual(await password().recheck({}), { ok: false, reason: "refused" });
  assert.equal(mock.requests.length, 0);
});

await check("key recheck: a deleted key is refused; another owner is refused", async () => {
  mock.reset();
  const m = key();
  const upstream = { username: "alice", apiKey: "key-alice" };
  assert.deepEqual(await m.recheck(upstream), { ok: true, upstream, person: { id: "alice", name: "alice" } });
  mock.keys.delete("key-alice");
  assert.deepEqual(await m.recheck(upstream), { ok: false, reason: "refused" });
  mock.keys.set("key-alice", "bob");
  assert.deepEqual(await m.recheck(upstream), { ok: false, reason: "refused" });
  assert.deepEqual(await m.recheck({ username: "alice" }), { ok: false, reason: "refused" });
});

await check("cleanup does nothing and calls nothing", async () => {
  mock.reset();
  assert.equal(await password().cleanup({ username: "alice" }), undefined);
  assert.equal(await key().cleanup({ username: "alice", apiKey: "key-alice" }), undefined);
  assert.equal(mock.requests.length, 0);
});

await check("no password or key appears in any result message or thrown error", async () => {
  assert.ok(messages.length > 10, `only ${messages.length} messages were collected`);
  for (const msg of messages) for (const s of SECRETS) assert.ok(!msg.includes(s), `a message contains a secret: ${msg}`);
});

server.close();
if (failed) {
  process.stderr.write(`${failed} check(s) failed\n`);
  process.exit(1);
}
