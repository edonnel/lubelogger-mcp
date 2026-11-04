// OAuth flow end to end, in-process: the real app from dist/ with a stub login method and a controllable clock.
// Drives the real HTTP endpoints with fetch; no browser and no Home Assistant involved.
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import fs from "node:fs/promises";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createApp } from "../dist/app.js";
import { validateConfig } from "../dist/config.js";

const PUBLIC_URL = "https://mcp.example.com";
const API_KEY = "test-api-key";
const REDIRECT_URI = "https://claude.example.com/api/mcp/auth_callback";
const MINUTE = 60_000;
const DAY = 24 * 60 * MINUTE;

// ---------- captured logs: kept, not printed, so the run stays quiet ----------
const logs = [];
const realError = console.error;
console.error = (...args) => {
  logs.push(args.map(String).join(" "));
};
// every secret the server hands out, checked against the logs at the end
const secrets = new Set();

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

// ---------- mock LubeLogger, enough for a propose and a commit ----------
const writes = [];
const mock = http.createServer((req, res) => {
  const url = new URL(req.url, "http://mock");
  const send = (code, obj) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  if (req.headers["x-api-key"] !== API_KEY) return send(401, { success: false, message: "Unauthorized" });
  if (req.method === "GET" && url.pathname === "/api/vehicles")
    return send(200, [{ id: 1, year: 2019, make: "Toyota", model: "Tacoma", licensePlate: "ABC123" }]);
  if (req.method === "GET" && url.pathname === "/api/vehicle/odometerrecords/latest") return send(200, 1000);
  if (req.method === "GET" && url.pathname.startsWith("/api/vehicle/")) return send(200, []);
  if (req.method === "POST" && url.pathname.endsWith("/add")) {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      writes.push(JSON.parse(raw));
      send(200, { success: true, message: "Record Added" });
    });
    return;
  }
  send(404, { success: false, message: "not found" });
});
await new Promise((r) => mock.listen(0, "127.0.0.1", r));
const mockUrl = `http://127.0.0.1:${mock.address().port}`;

// ---------- stub login method ----------
// start sends the browser straight back to /login/callback as whoever `stub.next` names
const stub = {
  next: "alice",
  recheckMode: "ok",
  cleaned: [],
  sessions: 0,
  async start(loginState, res) {
    secrets.add(loginState);
    res.redirect(302, `/login/callback?state=${encodeURIComponent(loginState)}&as=${encodeURIComponent(this.next)}`);
  },
  async finish(req) {
    const name = String(req.query.as);
    if (name !== "alice" && name !== "carol") return { refused: `${name} is not allowed <here> & "nowhere"` };
    this.sessions++;
    return { person: { id: `id-${name}`, name }, upstream: { session: `up-${name}-${this.sessions}`, name } };
  },
  async recheck(upstream) {
    if (this.recheckMode === "unavailable") return { ok: false, reason: "unavailable" };
    if (this.recheckMode === "refused") return { ok: false, reason: "refused" };
    if (this.recheckMode === "throws") throw new Error("connect ECONNREFUSED");
    return { ok: true, upstream, person: { id: `id-${upstream.name}`, name: upstream.name } };
  },
  async cleanup(upstream) {
    this.cleaned.push(upstream.session);
  },
};

// ---------- app lifecycle ----------
let clock = Date.now();
const now = () => clock;
const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), "oauth-ha-"));

function config(over = {}) {
  const r = validateConfig({
    LUBELOGGER_URL: mockUrl,
    LUBELOGGER_API_KEY: API_KEY,
    AUTH_MODE: "homeassistant",
    PUBLIC_URL,
    HOME_ASSISTANT_PUBLIC_URL: "https://ha.example.com",
    HOME_ASSISTANT_URL: "http://ha.example.com:8123",
    DATA_DIR: dataDir,
    ...over,
  });
  assert.ok(r.ok, JSON.stringify(r.problems));
  return r.config;
}

let running;
async function start() {
  const built = await createApp(config(), { loginMethod: stub, now });
  const server = await new Promise((resolve) => {
    const s = built.app.listen(0, "127.0.0.1", () => resolve(s));
  });
  running = { ...built, server, base: `http://127.0.0.1:${server.address().port}` };
  return running;
}
async function stop() {
  await running.close();
  await new Promise((r) => running.server.close(r));
  running = undefined;
}

// ---------- OAuth helpers ----------
const b64url = (buf) => buf.toString("base64url");
const get = (p, init = {}) => fetch(running.base + p, { redirect: "manual", ...init });
const form = (p, fields) =>
  fetch(running.base + p, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(fields).toString(),
  });

async function register() {
  const r = await fetch(running.base + "/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: [REDIRECT_URI], token_endpoint_auth_method: "none", client_name: "test client" }),
  });
  assert.equal(r.status, 201);
  return r.json();
}

// /authorize up to the login method's redirect; returns the callback path and the PKCE verifier
async function beginLogin(client, name) {
  stub.next = name;
  const verifier = b64url(randomBytes(32));
  const challenge = b64url(createHash("sha256").update(verifier).digest());
  const q = new URLSearchParams({
    response_type: "code",
    client_id: client.client_id,
    redirect_uri: REDIRECT_URI,
    code_challenge: challenge,
    code_challenge_method: "S256",
    state: "claude-state-123",
  });
  const r = await get(`/authorize?${q}`);
  assert.equal(r.status, 302, await r.text());
  return { callback: r.headers.get("location"), verifier };
}

// the whole browser leg: /authorize, the login method, /login/callback; returns the code
async function authorizeAs(client, name) {
  const { callback, verifier } = await beginLogin(client, name);
  const r = await get(callback);
  assert.equal(r.status, 302, await r.text());
  const back = new URL(r.headers.get("location"));
  assert.equal(`${back.origin}${back.pathname}`, REDIRECT_URI);
  assert.equal(back.searchParams.get("state"), "claude-state-123");
  const code = back.searchParams.get("code");
  assert.ok(code);
  secrets.add(code);
  return { code, verifier };
}

async function exchange(client, code, verifier) {
  return form("/token", {
    grant_type: "authorization_code",
    code,
    code_verifier: verifier,
    client_id: client.client_id,
    redirect_uri: REDIRECT_URI,
  });
}

function remember(tokens) {
  secrets.add(tokens.access_token);
  secrets.add(tokens.refresh_token);
  return tokens;
}

async function login(client, name) {
  const { code, verifier } = await authorizeAs(client, name);
  const r = await exchange(client, code, verifier);
  assert.equal(r.status, 200, await r.clone().text());
  const tokens = await r.json();
  assert.equal(tokens.token_type.toLowerCase(), "bearer");
  assert.equal(tokens.expires_in, 3600);
  return remember(tokens);
}

const refresh = (client, refreshToken) =>
  form("/token", { grant_type: "refresh_token", refresh_token: refreshToken, client_id: client.client_id });

async function mcpClient(accessToken) {
  const client = new Client({ name: "oauth-test", version: "0.0.0" });
  const transport = new StreamableHTTPClientTransport(new URL(`${running.base}/mcp`), {
    requestInit: { headers: { Authorization: `Bearer ${accessToken}` } },
  });
  await client.connect(transport);
  return client;
}

const mcpStatus = async (accessToken) => {
  const r = await fetch(`${running.base}/mcp`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      ...(accessToken ? { authorization: `Bearer ${accessToken}` } : {}),
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/list", params: {} }),
  });
  await r.body?.cancel();
  return r.status;
};

const text = (r) => r.content.map((c) => c.text).join("\n");

// ---------- tests ----------
await start();
const claude = await register();

await check("homeassistant mode without a login method refuses to start", async () => {
  await assert.rejects(createApp(config()), /Home Assistant login is not available/);
});

await check("GET /mcp without a token is 401 with a resource_metadata hint", async () => {
  const r = await get("/mcp");
  assert.equal(r.status, 401);
  assert.match(r.headers.get("www-authenticate") ?? "", /resource_metadata=/);
  assert.match(r.headers.get("www-authenticate"), /\/\.well-known\/oauth-protected-resource\/mcp/);
});

await check("POST /mcp without a token, or with a garbage one, is 401", async () => {
  assert.equal(await mcpStatus(undefined), 401);
  assert.equal(await mcpStatus("garbage-token"), 401);
});

await check("discovery documents are served", async () => {
  const as = await (await get("/.well-known/oauth-authorization-server")).json();
  assert.equal(new URL(as.issuer).href, new URL(PUBLIC_URL).href);
  assert.equal(as.registration_endpoint, `${PUBLIC_URL}/register`);
  assert.equal(as.authorization_endpoint, `${PUBLIC_URL}/authorize`);
  assert.equal(as.token_endpoint, `${PUBLIC_URL}/token`);
  const prm = await (await get("/.well-known/oauth-protected-resource/mcp")).json();
  assert.equal(prm.resource, `${PUBLIC_URL}/mcp`);
});

let alice;
await check("an allowed person gets tokens and can list tools", async () => {
  alice = await login(claude, "alice");
  const mcp = await mcpClient(alice.access_token);
  const { tools } = await mcp.listTools();
  assert.equal(tools.length, 12);
  await mcp.close();
  assert.ok(logs.some((l) => l.includes("alice")), "login is logged by name");
});

await check("an authorization code works once only", async () => {
  const { code, verifier } = await authorizeAs(claude, "carol");
  const first = await exchange(claude, code, verifier);
  assert.equal(first.status, 200);
  remember(await first.json());
  const second = await exchange(claude, code, verifier);
  assert.equal(second.status, 400);
  assert.equal((await second.json()).error, "invalid_grant");
});

await check("a refused person gets a 403 page and no code", async () => {
  const { callback } = await beginLogin(claude, "bob");
  const r = await get(callback);
  assert.equal(r.status, 403);
  assert.equal(r.headers.get("location"), null);
  const page = await r.text();
  assert.match(page, /bob is not allowed/);
  assert.match(page, /&lt;here&gt; &amp; &quot;nowhere&quot;/, "the refusal is escaped");
  assert.doesNotMatch(page, /<here>/);
  assert.ok(logs.some((l) => l.includes("bob")), "refusal is logged by name");
});

await check("an unknown, reused or expired login state gets a plain 400 page", async () => {
  const unknown = await get("/login/callback?state=nope&as=alice");
  assert.equal(unknown.status, 400);
  const unknownPage = await unknown.text();
  assert.match(unknownPage, /This login link has expired, start again from Claude/);
  assert.doesNotMatch(unknownPage, /at .*\.js/, "no stack trace");

  const missing = await get("/login/callback");
  assert.equal(missing.status, 400);

  const { callback } = await beginLogin(claude, "carol");
  const used = await get(callback);
  assert.equal(used.status, 302);
  secrets.add(new URL(used.headers.get("location")).searchParams.get("code"));
  const reused = await get(callback);
  assert.equal(reused.status, 400);
  assert.match(await reused.text(), /This login link has expired, start again from Claude/);

  const late = await beginLogin(claude, "carol");
  clock += 11 * MINUTE;
  const expired = await get(late.callback);
  assert.equal(expired.status, 400);
  assert.match(await expired.text(), /This login link has expired, start again from Claude/);
});

await check("refresh rotates the token; the old one works only within 60 seconds and gives the same pair", async () => {
  const r1 = await refresh(claude, alice.refresh_token);
  assert.equal(r1.status, 200);
  const next = remember(await r1.json());
  assert.notEqual(next.refresh_token, alice.refresh_token);
  assert.notEqual(next.access_token, alice.access_token);
  assert.equal(next.expires_in, 3600);

  clock += 30_000;
  const r2 = await refresh(claude, alice.refresh_token);
  assert.equal(r2.status, 200);
  assert.deepEqual(await r2.json(), next);

  assert.equal(await mcpStatus(next.access_token), 200);
  alice = next;
});

await check("two refreshes at once with the same token get the same pair", async () => {
  const [a, b] = await Promise.all([refresh(claude, alice.refresh_token), refresh(claude, alice.refresh_token)]);
  assert.equal(a.status, 200);
  assert.equal(b.status, 200);
  const pa = remember(await a.json());
  const pb = await b.json();
  assert.deepEqual(pa, pb);
  alice = pa;
  const again = await refresh(claude, alice.refresh_token);
  assert.equal(again.status, 200);
  alice = remember(await again.json());
});

await check("a stale refresh after 60 seconds is rejected", async () => {
  const old = alice.refresh_token;
  const r1 = await refresh(claude, old);
  alice = remember(await r1.json());
  clock += 61_000;
  const r2 = await refresh(claude, old);
  assert.equal(r2.status, 400);
  assert.equal((await r2.json()).error, "invalid_grant");
  // the current token is unaffected
  const r3 = await refresh(claude, alice.refresh_token);
  assert.equal(r3.status, 200);
  alice = remember(await r3.json());
});

await check("an unreachable login method gives 503 and keeps the refresh token", async () => {
  for (const mode of ["unavailable", "throws"]) {
    stub.recheckMode = mode;
    const r = await refresh(claude, alice.refresh_token);
    assert.equal(r.status, 503, mode);
    assert.equal((await r.json()).error, "temporarily_unavailable");
  }
  stub.recheckMode = "ok";
  const r = await refresh(claude, alice.refresh_token);
  assert.equal(r.status, 200);
  alice = remember(await r.json());
});

await check("a second login for the same client and person replaces the first connection", async () => {
  const before = stub.cleaned.length;
  const second = await login(claude, "alice");
  assert.equal(stub.cleaned.length, before + 1, "the replaced connection's upstream is cleaned up");
  assert.match(stub.cleaned.at(-1), /^up-alice-/);
  const r = await refresh(claude, alice.refresh_token);
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, "invalid_grant");
  assert.equal(await mcpStatus(alice.access_token), 401);
  assert.equal(await mcpStatus(second.access_token), 200);
  alice = second;
});

await check("a refusal on refresh ends the connection", async () => {
  const carol = await login(claude, "carol");
  stub.recheckMode = "refused";
  const before = stub.cleaned.length;
  const r = await refresh(claude, carol.refresh_token);
  stub.recheckMode = "ok";
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, "invalid_grant");
  assert.equal(stub.cleaned.length, before + 1);
  assert.equal(await mcpStatus(carol.access_token), 401);
  assert.equal((await refresh(claude, carol.refresh_token)).status, 400);
});

await check("revoking the refresh token ends the connection", async () => {
  const other = await register();
  const carol = await login(other, "carol");
  const before = stub.cleaned.length;
  const r = await form("/revoke", { token: carol.refresh_token, client_id: other.client_id });
  assert.equal(r.status, 200);
  assert.equal(stub.cleaned.length, before + 1);
  assert.equal(await mcpStatus(carol.access_token), 401);
  const again = await refresh(other, carol.refresh_token);
  assert.equal(again.status, 400);
});

await check("a refresh token from another client is refused", async () => {
  const other = await register();
  const r = await refresh(other, alice.refresh_token);
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, "invalid_grant");
});

await check("a confirmation proposed by alice cannot be committed by carol", async () => {
  const carolTokens = await login(claude, "carol");
  const asAlice = await mcpClient(alice.access_token);
  const asCarol = await mcpClient(carolTokens.access_token);
  const preview = await asAlice.callTool({
    name: "propose_odometer_record",
    arguments: { vehicle: "Tacoma", date: "2026-11-01", odometer: 1200 },
  });
  assert.ok(!preview.isError, text(preview));
  const token = text(preview).match(/Confirmation token: (\w+)/)[1];

  const stolen = await asCarol.callTool({ name: "commit_record", arguments: { confirmationToken: token } });
  assert.ok(stolen.isError);
  assert.match(text(stolen), /Unknown or expired confirmation token/);
  assert.equal(writes.length, 0);

  const mine = await asAlice.callTool({ name: "commit_record", arguments: { confirmationToken: token } });
  assert.ok(!mine.isError, text(mine));
  assert.equal(writes.length, 1);
  await asAlice.close();
  await asCarol.close();
});

await check("connections survive a restart", async () => {
  await stop();
  await start();
  assert.equal(await mcpStatus(alice.access_token), 401, "access tokens live in memory only");
  const r = await refresh(claude, alice.refresh_token);
  assert.equal(r.status, 200);
  alice = remember(await r.json());
  assert.equal(await mcpStatus(alice.access_token), 200);
});

await check("a connection unused for 90 days expires", async () => {
  const before = stub.cleaned.length;
  clock += 91 * DAY;
  const r = await refresh(claude, alice.refresh_token);
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, "invalid_grant");
  assert.equal(stub.cleaned.length, before + 1);
});

await check("refresh tokens are stored hashed", async () => {
  const raw = await fs.readFile(path.join(dataDir, "oauth.json"), "utf8");
  for (const s of secrets) assert.ok(!raw.includes(s), "no issued secret in the data file");
});

await check("logins are logged by name, never with a token or code", async () => {
  const all = logs.join("\n");
  assert.match(all, /alice/);
  assert.match(all, /bob/);
  assert.ok(secrets.size > 10);
  for (const s of secrets) assert.ok(!all.includes(s), "a secret reached the log");
});

await stop();
mock.close();
await fs.rm(dataDir, { recursive: true, force: true });
console.error = realError;

if (failed) {
  process.stderr.write(`${failed} OAuth check(s) failed\n`);
  process.exit(1);
}
console.log("all OAuth checks passed");
