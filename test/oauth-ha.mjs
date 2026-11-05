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
import { InvalidGrantError } from "@modelcontextprotocol/sdk/server/auth/errors.js";
import { WebSocketServer } from "ws";
import { createApp } from "../dist/app.js";
import { LoginProvider } from "../dist/auth/provider.js";
import { AuthStore, hashToken } from "../dist/auth/store.js";
import { validateConfig } from "../dist/config.js";
import { PendingStore } from "../dist/pending.js";

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
    if (name !== "alice" && name !== "carol")
      return { refused: `${name} is not allowed <here> & "nowhere"`, person: { id: `id-${name}`, name } };
    this.sessions++;
    return { person: { id: `id-${name}`, name }, upstream: { session: `up-${name}-${this.sessions}`, name } };
  },
  // when set, recheck waits on it: holds a refresh open
  gate: undefined,
  async recheck(upstream) {
    if (this.gate) await this.gate;
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
    ALLOWED_REDIRECT_HOSTS: "claude.example.com",
    ...over,
  });
  assert.ok(r.ok, JSON.stringify(r.problems));
  return r.config;
}

let running;
async function start() {
  const built = await createApp(config(), { loginMethods: { homeassistant: stub }, now });
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
const form = (p, fields, headers = {}) =>
  fetch(running.base + p, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded", ...headers },
    body: new URLSearchParams(fields).toString(),
  });

const registerRaw = (metadata) =>
  fetch(running.base + "/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ redirect_uris: [REDIRECT_URI], token_endpoint_auth_method: "none", client_name: "test client", ...metadata }),
  });

async function register(metadata = {}) {
  const r = await registerRaw(metadata);
  assert.equal(r.status, 201);
  return r.json();
}

const loginStateOf = (html) => {
  const m = html.match(/name="loginState" value="([^"]+)"/);
  assert.ok(m, "the approval page carries the login state");
  return m[1];
};

// the approval page's browser cookie, as "lm_login=<nonce>" ready for a Cookie header
const cookieOf = (response) => {
  const set = response.headers.getSetCookie().find((c) => c.startsWith("lm_login="));
  assert.ok(set, "the approval page sets the login cookie");
  assert.match(set, /HttpOnly/);
  assert.match(set, /Secure/);
  assert.match(set, /SameSite=Lax/);
  assert.match(set, /Path=\/login(;|$)/);
  return set.split(";")[0];
};

// pressing a sign-in method's button on the sign-in screen
const approve = (loginState, cookie, headers = {}, method = "homeassistant") =>
  form("/login", { loginState, method }, { ...(cookie ? { cookie } : {}), ...headers });

// the login method's return to /login/callback, from the browser that holds the cookie
const callBack = (begun) => get(begun.callback, { headers: { cookie: begun.cookie } });

// /authorize, shows the approval page; returns it with the login state and the PKCE verifier
async function openApproval(client, name) {
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
  const html = await r.text();
  assert.equal(r.status, 200, html);
  return { response: r, html, loginState: loginStateOf(html), verifier, cookie: cookieOf(r) };
}

// /authorize and the approval, up to the login method's redirect; returns the callback path and the PKCE verifier
async function beginLogin(client, name) {
  const { loginState, verifier, cookie } = await openApproval(client, name);
  const r = await approve(loginState, cookie);
  assert.equal(r.status, 302, await r.text());
  return { callback: r.headers.get("location"), verifier, cookie };
}

// the whole browser leg: /authorize, the login method, /login/callback; returns the code
async function authorizeAs(client, name, begin = beginLogin) {
  const begun = await begin(client, name);
  const { verifier } = begun;
  const r = await callBack(begun);
  assert.equal(r.status, 302, await r.text());
  const back = new URL(r.headers.get("location"));
  assert.equal(`${back.origin}${back.pathname}`, REDIRECT_URI);
  assert.equal(back.searchParams.get("state"), "claude-state-123");
  const code = back.searchParams.get("code");
  assert.ok(code);
  secrets.add(code);
  return { code, verifier };
}

async function exchange(client, code, verifier, redirectUri = REDIRECT_URI) {
  return form("/token", {
    grant_type: "authorization_code",
    code,
    code_verifier: verifier,
    client_id: client.client_id,
    redirect_uri: redirectUri,
  });
}

function remember(tokens) {
  secrets.add(tokens.access_token);
  secrets.add(tokens.refresh_token);
  return tokens;
}

async function login(client, name, begin = beginLogin) {
  const { code, verifier } = await authorizeAs(client, name, begin);
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
  const r = await callBack(await beginLogin(claude, "bob"));
  assert.equal(r.status, 403);
  assert.equal(r.headers.get("location"), null);
  const page = await r.text();
  assert.match(page, /bob is not allowed/);
  assert.match(page, /&lt;here&gt; &amp; &quot;nowhere&quot;/, "the refusal is escaped");
  assert.doesNotMatch(page, /<here>/);
  assert.ok(logs.some((l) => l.includes('login refused for "bob"')), "refusal is logged by name");
});

await check("an unknown, reused or expired login state gets a plain 400 page", async () => {
  const unknown = await get("/login/callback?state=nope&as=alice");
  assert.equal(unknown.status, 400);
  const unknownPage = await unknown.text();
  assert.match(unknownPage, /This login link has expired, start again from Claude/);
  assert.doesNotMatch(unknownPage, /at .*\.js/, "no stack trace");

  const missing = await get("/login/callback");
  assert.equal(missing.status, 400);

  const begun = await beginLogin(claude, "carol");
  const used = await callBack(begun);
  assert.equal(used.status, 302);
  secrets.add(new URL(used.headers.get("location")).searchParams.get("code"));
  const reused = await callBack(begun);
  assert.equal(reused.status, 400);
  assert.match(await reused.text(), /This login link has expired, start again from Claude/);

  const late = await beginLogin(claude, "carol");
  clock += 11 * MINUTE;
  const expired = await callBack(late);
  assert.equal(expired.status, 400);
  assert.match(await expired.text(), /This login link has expired, start again from Claude/);
});

await check("registration refuses redirect hosts that are not allowed", async () => {
  for (const uri of ["https://attacker.example.net/cb", "http://claude.example.com/cb", "https://claude.example.com.attacker.example.net/cb"]) {
    const r = await registerRaw({ redirect_uris: [REDIRECT_URI, uri] });
    assert.equal(r.status, 400, uri);
    assert.equal((await r.json()).error, "invalid_client_metadata");
  }
});

await check("/authorize shows an approval page naming the app and where it returns", async () => {
  const named = await register({ client_name: "<b>Sneaky</b> & co" });
  const { response, html } = await openApproval(named, "alice");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.match(response.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  assert.match(html, /&lt;b&gt;Sneaky&lt;\/b&gt; &amp; co/);
  assert.doesNotMatch(html, /<b>Sneaky/);
  assert.match(html, /claude\.example\.com/);
  assert.match(html, /<form method="post" action="\/login">/);
  assert.match(html, /<button type="submit" name="method" value="homeassistant">/);
  assert.match(html, /Continue with Home Assistant/);

  const unnamed = await register({ client_name: undefined });
  assert.match((await openApproval(unnamed, "alice")).html, /An unnamed app/);
});

await check("a login that was not approved is refused at the callback", async () => {
  const { loginState, cookie } = await openApproval(claude, "alice");
  const r = await get(`/login/callback?state=${encodeURIComponent(loginState)}&as=alice`, { headers: { cookie } });
  assert.equal(r.status, 400);
  assert.match(await r.text(), /This login link has expired, start again from Claude/);
  // and the state is spent: approving it afterwards does not revive it
  assert.equal((await approve(loginState, cookie)).status, 400);
});

await check("an unknown or expired approval gets the start-again page", async () => {
  const unknown = await approve("nope");
  assert.equal(unknown.status, 400);
  assert.match(await unknown.text(), /This login link has expired, start again from Claude/);
  const { loginState, cookie } = await openApproval(claude, "alice");
  clock += 11 * MINUTE;
  const late = await approve(loginState, cookie);
  assert.equal(late.status, 400);
  assert.match(await late.text(), /This login link has expired, start again from Claude/);
});

await check("an approval from a browser that did not see the approval page is refused", async () => {
  const { loginState, cookie } = await openApproval(claude, "alice");
  for (const [why, r] of [
    ["no cookie", await approve(loginState)],
    ["wrong cookie", await approve(loginState, "lm_login=not-the-nonce")],
    ["foreign origin", await approve(loginState, cookie, { origin: "https://attacker.example.net" })],
  ]) {
    assert.equal(r.status, 400, why);
    assert.match(await r.text(), /This login link has expired, start again from Claude/, why);
    assert.equal(r.headers.get("location"), null, why);
  }
  // none of those spent it: the browser that saw the page can still approve, and the same origin is fine
  const r = await approve(loginState, cookie, { origin: PUBLIC_URL });
  assert.equal(r.status, 302);
});

await check("a callback without the login cookie is refused, and the cookie is cleared after the callback", async () => {
  const begun = await beginLogin(claude, "carol");
  const bare = await get(begun.callback);
  assert.equal(bare.status, 400);
  assert.match(await bare.text(), /This login link has expired, start again from Claude/);

  const again = await beginLogin(claude, "carol");
  const wrong = await callBack({ ...again, cookie: "lm_login=not-the-nonce" });
  assert.equal(wrong.status, 400);

  const ok = await beginLogin(claude, "carol");
  const r = await callBack(ok);
  assert.equal(r.status, 302);
  secrets.add(new URL(r.headers.get("location")).searchParams.get("code"));
  const cleared = r.headers.getSetCookie().find((c) => c.startsWith("lm_login="));
  assert.ok(cleared, "the callback clears the login cookie");
  assert.match(cleared, /Max-Age=0/);
  assert.match(cleared, /Path=\/login(;|$)/);
});

await check("a malformed or oversize approval body gets a plain page with no stack trace", async () => {
  const marker = "body-marker-7f3a";
  const big = await fetch(running.base + "/login", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: `loginState=${marker}${"x".repeat(8 * 1024)}`,
  });
  const charset = await fetch(running.base + "/login", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded; charset=x-not-a-charset" },
    body: `loginState=${marker}`,
  });
  for (const [why, r] of [["oversize", big], ["bad charset", charset]]) {
    assert.equal(r.status, 400, why);
    assert.match(r.headers.get("content-type") ?? "", /text\/html/, why);
    const page = await r.text();
    assert.doesNotMatch(page, /\bat /, `${why}: no stack trace`);
    assert.doesNotMatch(page, /Error/, `${why}: no error name`);
    assert.ok(!page.includes(marker), `${why}: no request content`);
  }
});

await check("the sign-in screen names the app, its return host, and one button per method", async () => {
  const claude = await register({ client_name: "Claude <b>x</b>" });
  const { html, response } = await openApproval(claude, "alice");
  assert.match(html, /Sign in to LubeLogger MCP/);
  assert.match(html, /Claude &lt;b&gt;x&lt;\/b&gt;/);
  assert.match(html, /claude\.example\.com/);
  assert.equal((html.match(/name="method"/g) ?? []).length, 1);
  assert.equal(response.headers.get("content-security-policy"), "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'");
  assert.equal(response.headers.get("x-frame-options"), "DENY");
  assert.doesNotMatch(html, /<script/i);
});

await check("a method that is not on, or no method, gets a 400 page, keeps the state, and is logged quoted", async () => {
  const claude = await register();
  const { loginState, cookie } = await openApproval(claude, "alice");
  for (const method of ["oidc", "", "evil\nline"]) {
    const r = await approve(loginState, cookie, {}, method);
    assert.equal(r.status, 400);
    assert.match(await r.text(), /not available/);
  }
  // a form with no method field at all, such as a release 1 approval page still open in a tab
  const bare = await form("/login", { loginState }, { cookie });
  assert.equal(bare.status, 400);
  assert.match(await bare.text(), /not available/);
  assert.ok(logs.some((l) => l.includes(JSON.stringify("evil\nline"))));
  assert.ok(!logs.some((l) => l.includes("evil\nline") && !l.includes(JSON.stringify("evil\nline"))));
  const ok = await approve(loginState, cookie);
  assert.equal(ok.status, 302);
});

await check("pressing the button twice does not break the login under way", async () => {
  const claude = await register();
  const { loginState, cookie, verifier } = await openApproval(claude, "alice");
  const first = await approve(loginState, cookie);
  assert.equal(first.status, 302);
  const second = await approve(loginState, cookie);
  assert.equal(second.status, 400);
  assert.match(await second.text(), /This login link has expired, start again from Claude/);
  const back = await get(first.headers.get("location"), { headers: { cookie } });
  assert.equal(back.status, 302);
  // and the code from that callback still exchanges for tokens
  const code = new URL(back.headers.get("location")).searchParams.get("code");
  secrets.add(code);
  const r = await exchange(claude, code, verifier);
  assert.equal(r.status, 200);
  remember(await r.json());
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

await check("another client cannot join a refresh in progress", async () => {
  const thief = await register();
  let release;
  stub.gate = new Promise((r) => (release = r));
  const mine = refresh(claude, alice.refresh_token);
  await new Promise((r) => setTimeout(r, 50));
  // fired while the first refresh is held open; the gate is released without waiting on it, so a join cannot deadlock
  const theirsPending = refresh(thief, alice.refresh_token);
  await new Promise((r) => setTimeout(r, 50));
  release();
  stub.gate = undefined;
  const theirs = await theirsPending;
  assert.equal(theirs.status, 400);
  const body = await theirs.json();
  assert.equal(body.error, "invalid_grant");
  assert.equal(body.access_token, undefined);
  const r = await mine;
  assert.equal(r.status, 200);
  alice = remember(await r.json());
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

await check("a refresh token two rotations old is rejected even within 60 seconds", async () => {
  const t0 = alice.refresh_token;
  const r1 = await refresh(claude, t0);
  assert.equal(r1.status, 200);
  const t1 = remember(await r1.json());
  const r2 = await refresh(claude, t1.refresh_token);
  assert.equal(r2.status, 200);
  alice = remember(await r2.json());
  clock += 5_000;
  const old = await refresh(claude, t0);
  assert.equal(old.status, 400);
  assert.equal((await old.json()).error, "invalid_grant");
  // the current token is unaffected
  const r3 = await refresh(claude, alice.refresh_token);
  assert.equal(r3.status, 200);
  alice = remember(await r3.json());
});

await check("an authorization code redeemed by another client is invalid_grant", async () => {
  const other = await register();
  const { code, verifier } = await authorizeAs(claude, "carol");
  const r = await exchange(other, code, verifier);
  assert.equal(r.status, 400);
  const body = await r.json();
  assert.equal(body.error, "invalid_grant");
  assert.equal(body.access_token, undefined);
  // the rightful client can still redeem it
  const mine = await exchange(claude, code, verifier);
  assert.equal(mine.status, 200);
  remember(await mine.json());
});

await check("a redirect_uri mismatch at the exchange is invalid_grant and ends the upstream session", async () => {
  const { code, verifier } = await authorizeAs(claude, "carol");
  const before = stub.cleaned.length;
  const r = await exchange(claude, code, verifier, "https://claude.example.com/elsewhere");
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, "invalid_grant");
  assert.equal(stub.cleaned.length, before + 1, "the upstream session behind the code is cleaned up");
  assert.match(stub.cleaned.at(-1), /^up-carol-/);
  // and the code is spent
  assert.equal((await exchange(claude, code, verifier)).status, 400);
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

await check("confirmations are owned by method and person", async () => {
  // the app's own PendingStore, watched through its prototype
  const owners = [];
  const add = PendingStore.prototype.add;
  PendingStore.prototype.add = function (rec) {
    owners.push(rec.owner);
    return add.call(this, rec);
  };
  try {
    const asAlice = await mcpClient(alice.access_token);
    const preview = await asAlice.callTool({
      name: "propose_odometer_record",
      arguments: { vehicle: "Tacoma", date: "2026-11-02", odometer: 1300 },
    });
    assert.ok(!preview.isError, text(preview));
    await asAlice.close();
  } finally {
    PendingStore.prototype.add = add;
  }
  assert.deepEqual(owners, ["homeassistant:id-alice"]);
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

await check("a release 1 connection refreshes without a new login", async () => {
  const client = await register();
  const tokens = await login(client, "carol");
  await stop();
  // write oauth.json as release 1 did: no connection records its method
  const file = path.join(dataDir, "oauth.json");
  const data = JSON.parse(await fs.readFile(file, "utf8"));
  for (const c of Object.values(data.connections)) delete c.method;
  await fs.writeFile(file, JSON.stringify(data, null, 2));
  await start();
  const r = await refresh(client, tokens.refresh_token);
  assert.equal(r.status, 200);
  const next = remember(await r.json());
  assert.equal(await mcpStatus(next.access_token), 200);
  // the next write records the method on every connection
  const stored = Object.values(JSON.parse(await fs.readFile(file, "utf8")).connections);
  assert.ok(stored.length > 0);
  for (const c of stored) assert.equal(c.method, "homeassistant");
});

await check("a connection unused for 90 days expires", async () => {
  const before = stub.cleaned.length;
  clock += 91 * DAY;
  const r = await refresh(claude, alice.refresh_token);
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, "invalid_grant");
  assert.equal(stub.cleaned.length, before + 1);
});

const storedConnections = async () =>
  Object.values(JSON.parse(await fs.readFile(path.join(dataDir, "oauth.json"), "utf8")).connections);

await check("expired connections that are never presented again are purged at startup", async () => {
  // every connection left from the tests above is now more than 90 days unused, and none is presented again
  const left = await storedConnections();
  assert.ok(left.length > 0);
  const before = stub.cleaned.length;
  await stop();
  await start();
  assert.equal(stub.cleaned.length, before + left.length, "each purged connection's upstream is cleaned up");
  for (const c of left) assert.ok(stub.cleaned.includes(c.upstream.session));
  assert.deepEqual(await storedConnections(), []);
  assert.ok(logs.some((l) => /disconnected "(alice|carol)" \(expired after 90 days unused\)/.test(l)));
});

await check("expired connections are purged by the periodic sweep", async () => {
  const carol = await login(claude, "carol");
  assert.equal((await storedConnections()).length, 1);
  const before = stub.cleaned.length;
  clock += 91 * DAY;
  // any browser request sweeps; the purge runs in the background
  await openApproval(claude, "alice");
  for (let i = 0; i < 50 && stub.cleaned.length === before; i++) await new Promise((r) => setTimeout(r, 10));
  assert.equal(stub.cleaned.length, before + 1);
  assert.match(stub.cleaned.at(-1), /^up-carol-/);
  assert.deepEqual(await storedConnections(), []);
  assert.equal((await refresh(claude, carol.refresh_token)).status, 400);
});

await check("refresh tokens are stored hashed", async () => {
  const raw = await fs.readFile(path.join(dataDir, "oauth.json"), "utf8");
  for (const s of secrets) assert.ok(!raw.includes(s), "no issued secret in the data file");
});

await check("a connection whose method is switched off is ended at refresh, and its cleanup is skipped with a log line", async () => {
  const offDir = await fs.mkdtemp(path.join(os.tmpdir(), "oauth-off-"));
  try {
    const store = await AuthStore.open(offDir, now);
    const client = { client_id: "client-off", redirect_uris: [REDIRECT_URI] };
    const refreshToken = randomBytes(32).toString("base64url");
    secrets.add(refreshToken);
    const connection = (id, name, hash) => ({
      id,
      clientId: client.client_id,
      method: "homeassistant",
      person: { id: `id-${name}`, name },
      upstream: { session: `up-${name}-off`, name },
      refreshHash: hash,
      lastUsedAt: clock,
    });
    await store.putConnection(connection("conn-bob", "bob", hashToken(refreshToken)));
    await store.putConnection(connection("conn-carol", "carol", hashToken(randomBytes(32).toString("base64url"))));

    // another method's stub: it must never be asked about a homeassistant connection
    const other = { ...stub, cleaned: [] };
    assert.throws(() => new LoginProvider(store, new Map(), now), "a provider needs at least one method");
    const provider = new LoginProvider(store, new Map([["oidc", other]]), now);
    const before = stub.cleaned.length;

    await assert.rejects(provider.exchangeRefreshToken(client, refreshToken), InvalidGrantError);
    assert.ok(!store.connections().some((c) => c.id === "conn-bob"), "the connection is gone");
    assert.ok(logs.some((l) => l.includes('upstream session for "bob" could not be revoked (sign-in method switched off)')));
    assert.ok(logs.some((l) => l.includes('disconnected "bob" (sign-in method switched off)')));

    // the purge ends the ones that are never presented again
    await provider.purgeExpired();
    assert.deepEqual(store.connections(), []);
    assert.ok(logs.some((l) => l.includes('upstream session for "carol" could not be revoked (sign-in method switched off)')));

    assert.equal(stub.cleaned.length, before, "no cleanup ran through any method");
    assert.deepEqual(other.cleaned, []);
    await provider.close();
  } finally {
    await fs.rm(offDir, { recursive: true, force: true });
  }
});

await check("logins are logged by name, never with a token or code", async () => {
  const all = logs.join("\n");
  assert.match(all, /alice/);
  assert.match(all, /bob/);
  assert.ok(secrets.size > 10);
  for (const s of secrets) assert.ok(!all.includes(s), "a secret reached the log");
});

await stop();

// ---------- Home Assistant: the real login method against a mock HA ----------
// The mock speaks HA's OAuth endpoints and the WebSocket auth handshake plus auth/current_user.
// Its /auth/authorize skips the login form: `&as=<user>` picks who logs in.
const HA_CLIENT_ID = `${PUBLIC_URL}/`;
const HA_REDIRECT_URI = `${PUBLIC_URL}/login/callback`;
const haUsers = {
  "admin-user": { id: "id-admin-user", name: "Admin Person", is_owner: false, is_admin: true },
  "plain-user": { id: "id-plain-user", name: "Plain Person", is_owner: false, is_admin: false },
};
const ha = {
  // when set, every HTTP request is answered with this status
  failWith: undefined,
  // when true, WebSocket upgrades are dropped
  wsDown: false,
  codes: new Map(),
  // refresh token -> { user, valid }
  sessions: new Map(),
  // access token -> refresh token
  access: new Map(),
  issued: [],
  revoked: [],
  live(user) {
    return [...this.sessions].filter(([, s]) => s.valid && s.user === user).map(([t]) => t);
  },
  // what deleting a session in the HA profile does: the refresh token stops working
  invalidate(refreshToken) {
    this.sessions.get(refreshToken).valid = false;
  },
};
const haSecret = () => {
  const s = randomBytes(24).toString("hex");
  secrets.add(s);
  return s;
};

const readForm = (req) =>
  new Promise((resolve) => {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => resolve(Object.fromEntries(new URLSearchParams(raw))));
  });

const haServer = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://ha");
  const json = (code, obj) => {
    res.writeHead(code, { "content-type": "application/json" });
    res.end(JSON.stringify(obj));
  };
  if (ha.failWith) return json(ha.failWith, { message: "Service unavailable" });

  if (req.method === "GET" && url.pathname === "/auth/authorize") {
    const p = url.searchParams;
    if (
      p.get("response_type") !== "code" ||
      p.get("client_id") !== HA_CLIENT_ID ||
      p.get("redirect_uri") !== HA_REDIRECT_URI ||
      !p.get("state") ||
      !haUsers[p.get("as")]
    )
      return json(400, { error: "invalid_request" });
    const code = haSecret();
    ha.codes.set(code, p.get("as"));
    const back = new URL(p.get("redirect_uri"));
    back.searchParams.set("code", code);
    back.searchParams.set("state", p.get("state"));
    res.writeHead(302, { location: back.href });
    return res.end();
  }

  if (req.method === "POST" && url.pathname === "/auth/token") {
    const body = await readForm(req);
    if (body.client_id !== HA_CLIENT_ID) return json(400, { error: "invalid_request", error_description: "Invalid client id" });
    if (body.grant_type === "authorization_code") {
      const user = ha.codes.get(body.code);
      ha.codes.delete(body.code);
      if (!user) return json(400, { error: "invalid_request", error_description: "Invalid code" });
      const refreshToken = haSecret();
      const accessToken = haSecret();
      ha.sessions.set(refreshToken, { user, valid: true });
      ha.access.set(accessToken, refreshToken);
      ha.issued.push(refreshToken);
      return json(200, { access_token: accessToken, token_type: "Bearer", refresh_token: refreshToken, expires_in: 1800 });
    }
    if (body.grant_type === "refresh_token") {
      if (!ha.sessions.get(body.refresh_token)?.valid) return json(400, { error: "invalid_grant" });
      const accessToken = haSecret();
      ha.access.set(accessToken, body.refresh_token);
      return json(200, { access_token: accessToken, token_type: "Bearer", expires_in: 1800 });
    }
    return json(400, { error: "unsupported_grant_type" });
  }

  if (req.method === "POST" && url.pathname === "/auth/revoke") {
    const body = await readForm(req);
    const session = ha.sessions.get(body.token);
    if (session?.valid) {
      session.valid = false;
      ha.revoked.push(body.token);
    }
    res.writeHead(200);
    return res.end();
  }

  json(404, { message: "not found" });
});

const wss = new WebSocketServer({ noServer: true });
haServer.on("upgrade", (req, socket, head) => {
  if (ha.failWith || ha.wsDown || new URL(req.url, "http://ha").pathname !== "/api/websocket") {
    socket.destroy();
    return;
  }
  wss.handleUpgrade(req, socket, head, (ws) => {
    let user;
    ws.send(JSON.stringify({ type: "auth_required", ha_version: "2026.3.1" }));
    ws.on("message", (raw) => {
      const msg = JSON.parse(String(raw));
      if (!user) {
        const refreshToken = msg.type === "auth" ? ha.access.get(msg.access_token) : undefined;
        const session = refreshToken && ha.sessions.get(refreshToken);
        if (!session?.valid) {
          ws.send(JSON.stringify({ type: "auth_invalid", message: "Invalid access token or password" }));
          ws.close();
          return;
        }
        user = session.user;
        ws.send(JSON.stringify({ type: "auth_ok", ha_version: "2026.3.1" }));
        return;
      }
      if (msg.type === "auth/current_user")
        ws.send(JSON.stringify({ id: msg.id, type: "result", success: true, result: { ...haUsers[user], credentials: [], mfa_modules: [] } }));
    });
  });
});

let haPort = 0;
async function haListen() {
  await new Promise((r) => haServer.listen(haPort, "127.0.0.1", r));
  haPort = haServer.address().port;
}
async function haStop() {
  for (const c of wss.clients) c.terminate();
  await new Promise((r) => {
    haServer.close(r);
    haServer.closeAllConnections();
  });
}
await haListen();
const haBase = `http://127.0.0.1:${haPort}`;

const haDataDir = await fs.mkdtemp(path.join(os.tmpdir(), "oauth-ha-real-"));

// homeassistant mode with nothing injected but the clock: the app builds the real HomeAssistantLogin
async function startHa() {
  const built = await createApp(
    config({ HOME_ASSISTANT_PUBLIC_URL: haBase, HOME_ASSISTANT_URL: haBase, DATA_DIR: haDataDir }),
    { now },
  );
  const server = await new Promise((resolve) => {
    const s = built.app.listen(0, "127.0.0.1", () => resolve(s));
  });
  running = { ...built, server, base: `http://127.0.0.1:${server.address().port}` };
  return running;
}

// /authorize, Approve, then HA's authorize page as `user`; returns our callback path and the PKCE verifier
async function haBeginLogin(client, user) {
  const { callback: toHa, verifier, cookie } = await beginLogin(client, user);
  const u = new URL(toHa);
  assert.equal(`${u.origin}${u.pathname}`, `${haBase}/auth/authorize`);
  assert.deepEqual([...u.searchParams.keys()].sort(), ["client_id", "redirect_uri", "response_type", "state"]);
  assert.equal(u.searchParams.get("response_type"), "code");
  assert.equal(u.searchParams.get("client_id"), HA_CLIENT_ID);
  assert.equal(u.searchParams.get("redirect_uri"), HA_REDIRECT_URI);
  secrets.add(u.searchParams.get("state"));
  u.searchParams.set("as", user);
  const r = await fetch(u, { redirect: "manual" });
  assert.equal(r.status, 302, await r.text());
  const back = new URL(r.headers.get("location"));
  assert.equal(`${back.origin}${back.pathname}`, HA_REDIRECT_URI);
  return { callback: `${back.pathname}${back.search}`, verifier, cookie };
}

const haLogin = (client, user) => login(client, user, haBeginLogin);

const noStack = (page) => assert.doesNotMatch(page, /at .*\.js/, "no stack trace");

await startHa();
const claudeHa = await register();

await check("GET / names the app for Home Assistant", async () => {
  const r = await get("/");
  assert.equal(r.status, 200);
  assert.match(r.headers.get("content-type") ?? "", /text\/html/);
  const page = await r.text();
  assert.match(page, /<title>LubeLogger MCP<\/title>/);
  assert.match(page, /<link rel="redirect_uri" href="https:\/\/mcp\.example\.com\/login\/callback">/);
});

await check("an HA admin connects end to end and lists tools", async () => {
  const tokens = await haLogin(claudeHa, "admin-user");
  const mcp = await mcpClient(tokens.access_token);
  const { tools } = await mcp.listTools();
  assert.equal(tools.length, 12);
  await mcp.close();
  assert.ok(logs.some((l) => l.includes('login by "Admin Person"')), "login is logged by name");
  assert.equal(ha.live("admin-user").length, 1, "one HA session for the connection");
});

await check("a non-admin is refused and their HA session is revoked", async () => {
  const r = await callBack(await haBeginLogin(claudeHa, "plain-user"));
  assert.equal(r.status, 403);
  assert.equal(r.headers.get("location"), null);
  const page = await r.text();
  assert.match(page, /Only Home Assistant administrators can connect\./);
  noStack(page);
  assert.equal(ha.revoked.length, 1);
  assert.deepEqual(ha.live("plain-user"), []);
  assert.ok(
    logs.some((l) => l.includes('login refused for "Plain Person": "Only Home Assistant administrators can connect."')),
    "refusal is logged with the person's name",
  );
});

await check("an admin login after a refused one from the same client works", async () => {
  const client = await register();
  assert.equal((await callBack(await haBeginLogin(client, "plain-user"))).status, 403);
  assert.deepEqual(ha.live("plain-user"), [], "the refusal leaves no HA session behind");
  const tokens = await haLogin(client, "admin-user");
  assert.equal(await mcpStatus(tokens.access_token), 200);
  const r = await refresh(client, tokens.refresh_token);
  assert.equal(r.status, 200);
  remember(await r.json());
});

await check("deleting the HA session ends the connection at the next refresh", async () => {
  const client = await register();
  const tokens = await haLogin(client, "admin-user");
  ha.invalidate(ha.issued.at(-1));
  const r = await refresh(client, tokens.refresh_token);
  assert.equal(r.status, 400);
  assert.equal((await r.json()).error, "invalid_grant");
  assert.equal(await mcpStatus(tokens.access_token), 401);
  assert.equal((await refresh(client, tokens.refresh_token)).status, 400);
});

await check("removing admin rights ends the connection at the next refresh", async () => {
  const client = await register();
  const tokens = await haLogin(client, "admin-user");
  const haToken = ha.issued.at(-1);
  haUsers["admin-user"].is_admin = false;
  try {
    const r = await refresh(client, tokens.refresh_token);
    assert.equal(r.status, 400);
    assert.equal((await r.json()).error, "invalid_grant");
  } finally {
    haUsers["admin-user"].is_admin = true;
  }
  assert.equal(await mcpStatus(tokens.access_token), 401);
  assert.ok(ha.revoked.includes(haToken), "the ended connection's HA session is revoked");
});

await check("HA returning 503 gives temporarily_unavailable and keeps the refresh token", async () => {
  const client = await register();
  const tokens = await haLogin(client, "admin-user");
  ha.failWith = 503;
  try {
    const r = await refresh(client, tokens.refresh_token);
    assert.equal(r.status, 503);
    assert.equal((await r.json()).error, "temporarily_unavailable");
  } finally {
    ha.failWith = undefined;
  }
  const r = await refresh(client, tokens.refresh_token);
  assert.equal(r.status, 200);
  remember(await r.json());
});

await check("a WebSocket failure during refresh gives temporarily_unavailable", async () => {
  const client = await register();
  const tokens = await haLogin(client, "admin-user");
  ha.wsDown = true;
  try {
    const r = await refresh(client, tokens.refresh_token);
    assert.equal(r.status, 503);
    assert.equal((await r.json()).error, "temporarily_unavailable");
  } finally {
    ha.wsDown = false;
  }
  const r = await refresh(client, tokens.refresh_token);
  assert.equal(r.status, 200);
  remember(await r.json());
});

await check("HA unreachable gives temporarily_unavailable", async () => {
  const client = await register();
  const tokens = await haLogin(client, "admin-user");
  await haStop();
  try {
    const r = await refresh(client, tokens.refresh_token);
    assert.equal(r.status, 503);
    assert.equal((await r.json()).error, "temporarily_unavailable");
  } finally {
    await haListen();
  }
  const r = await refresh(client, tokens.refresh_token);
  assert.equal(r.status, 200);
  remember(await r.json());
});

await check("replacing a connection revokes the old HA session", async () => {
  const client = await register();
  const first = await haLogin(client, "admin-user");
  const oldHaToken = ha.issued.at(-1);
  const second = await haLogin(client, "admin-user");
  assert.ok(ha.revoked.includes(oldHaToken), "the replaced connection's HA session is revoked");
  assert.ok(ha.sessions.get(ha.issued.at(-1)).valid, "the new HA session is live");
  assert.equal((await refresh(client, first.refresh_token)).status, 400);
  assert.equal(await mcpStatus(second.access_token), 200);
});

await check("an expired or unknown login state shows the start-again page with 400", async () => {
  const r = await get("/login/callback?state=nope&code=x");
  assert.equal(r.status, 400);
  const page = await r.text();
  assert.match(page, /start again from Claude/);
  noStack(page);
});

await check("HA unreachable during login shows a readable error page", async () => {
  const begun = await haBeginLogin(claudeHa, "admin-user");
  await haStop();
  let r;
  try {
    r = await callBack(begun);
  } finally {
    await haListen();
  }
  assert.equal(r.status, 502);
  assert.equal(r.headers.get("location"), null);
  const page = await r.text();
  assert.match(page, /The login could not be completed\. Start again from Claude\./);
  noStack(page);
});

await check("HA logins and refusals are logged by name, never with a token or code", async () => {
  const all = logs.join("\n");
  assert.match(all, /Admin Person/);
  assert.match(all, /Plain Person/);
  assert.ok(ha.issued.length > 5);
  for (const s of secrets) assert.ok(!all.includes(s), "a secret reached the log");
});

await stop();
await haStop();
await fs.rm(haDataDir, { recursive: true, force: true });

mock.close();
await fs.rm(dataDir, { recursive: true, force: true });
console.error = realError;

if (failed) {
  process.stderr.write(`${failed} OAuth check(s) failed\n`);
  process.exit(1);
}
console.log("all OAuth checks passed");
