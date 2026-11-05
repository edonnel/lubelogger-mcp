// The OpenID Connect login method against a mock identity provider on node:http.
// The method is driven directly: start() with a fake response, finish() with a fake request.
import assert from "node:assert/strict";
import { createHash, createSign, generateKeyPairSync } from "node:crypto";
import http from "node:http";
import { OidcLogin } from "../dist/auth/oidc.js";

const PUBLIC_URL = "https://mcp.example.com";
const CLIENT_ID = "lubelogger-mcp";
const CLIENT_SECRET = "test-client-secret-5f1e2d";
const MINUTE = 60_000;

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

// every secret value seen in the run, and every error message thrown, compared at the end
const secrets = new Set([CLIENT_SECRET, "c1"]);
const messages = [];
async function throws(fn) {
  try {
    await fn();
  } catch (err) {
    messages.push(err instanceof Error ? err.message : String(err));
    return err;
  }
  assert.fail("expected a throw");
}

// ---------- the mock identity provider ----------
const b64url = (buf) => Buffer.from(buf).toString("base64url");
const goodKey = generateKeyPairSync("rsa", { modulusLength: 2048 });
const otherKey = generateKeyPairSync("rsa", { modulusLength: 2048 });
const jwk = { ...goodKey.publicKey.export({ format: "jwk" }), kid: "k1", alg: "RS256", use: "sig" };

function sign(claims, key = goodKey.privateKey) {
  const head = b64url(JSON.stringify({ alg: "RS256", typ: "JWT", kid: "k1" }));
  const body = b64url(JSON.stringify(claims));
  const s = createSign("RSA-SHA256").update(`${head}.${body}`).sign(key);
  return `${head}.${body}.${b64url(s)}`;
}

const idp = {
  port: 0,
  // a path the issuer lives under, e.g. "/application/o/mcp/"; its endpoints hang off it
  base: "",
  server: undefined,
  revocation: true,
  scopes: ["openid", "email", "profile", "offline_access"],
  // per test: claims merged into the next ID token, and how the token endpoint answers
  claims: {},
  signWith: undefined,
  nonce: undefined,
  codeChallenge: undefined,
  tokenStatus: 200,
  tokenError: undefined,
  issueRefresh: true,
  idTokenOnRefresh: true,
  counter: 0,
  tokenBodies: [],
  tokenAuth: [],
  revoked: [],
};
const issuer = () => `http://127.0.0.1:${idp.port}${idp.base}`;
const root = () => `http://127.0.0.1:${idp.port}${idp.base.replace(/\/$/, "")}`;

function baseClaims() {
  const now = Math.floor(Date.now() / 1000);
  return {
    iss: issuer(),
    aud: CLIENT_ID,
    sub: "sub-alice",
    iat: now,
    exp: now + 3600,
    name: "Alice",
    email: "alice@example.com",
    email_verified: true,
  };
}

function newSecretValue(prefix) {
  const v = `${prefix}-${++idp.counter}-${Math.random().toString(36).slice(2)}`;
  secrets.add(v);
  return v;
}

async function readBody(req) {
  let raw = "";
  for await (const c of req) raw += c;
  return new URLSearchParams(raw);
}

async function handle(req, res) {
  const url = new URL(req.url, issuer());
  const prefix = idp.base.replace(/\/$/, "");
  if (prefix && !url.pathname.startsWith(`${prefix}/`)) return res.writeHead(404).end();
  url.pathname = url.pathname.slice(prefix.length);
  const send = (code, obj) => {
    res.writeHead(code, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify(obj));
  };

  if (req.method === "GET" && url.pathname === "/.well-known/openid-configuration") {
    const doc = {
      issuer: issuer(),
      authorization_endpoint: `${root()}/authorize`,
      token_endpoint: `${root()}/token`,
      jwks_uri: `${root()}/jwks`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["client_secret_basic"],
      scopes_supported: idp.scopes,
    };
    if (idp.revocation) doc.revocation_endpoint = `${root()}/revoke`;
    return send(200, doc);
  }
  if (req.method === "GET" && url.pathname === "/jwks") return send(200, { keys: [jwk] });
  if (req.method === "POST" && url.pathname === "/token") {
    const body = await readBody(req);
    idp.tokenBodies.push(body);
    idp.tokenAuth.push(req.headers.authorization ?? "");
    if (idp.challenge) {
      res.writeHead(401, { "content-type": "application/json", "www-authenticate": 'Basic realm="idp", error="invalid_client"' });
      return res.end(JSON.stringify({ error: "invalid_client" }));
    }
    if (idp.tokenStatus !== 200) {
      if (idp.tokenError) return send(idp.tokenStatus, { error: idp.tokenError });
      res.writeHead(idp.tokenStatus, { "content-type": "text/plain" });
      return res.end("down for maintenance");
    }
    const grant = body.get("grant_type");
    const claims = { ...baseClaims(), ...idp.claims };
    if (grant === "authorization_code") {
      if (body.get("code") !== "c1") return send(400, { error: "invalid_grant" });
      const verifier = body.get("code_verifier") ?? "";
      if (createHash("sha256").update(verifier).digest("base64url") !== idp.codeChallenge)
        return send(400, { error: "invalid_grant" });
      if (idp.nonce !== undefined && !("nonce" in idp.claims)) claims.nonce = idp.nonce;
    } else if (grant !== "refresh_token") {
      return send(400, { error: "unsupported_grant_type" });
    }
    for (const [k, v] of Object.entries(claims)) if (v === undefined) delete claims[k];
    const answer = { access_token: newSecretValue("at"), token_type: "Bearer", expires_in: 3600 };
    if (grant === "authorization_code" || idp.idTokenOnRefresh) {
      answer.id_token = sign(claims, idp.signWith);
      secrets.add(answer.id_token);
    }
    if (idp.issueRefresh) answer.refresh_token = newSecretValue("rt");
    return send(200, answer);
  }
  if (req.method === "POST" && url.pathname === "/revoke") {
    const body = await readBody(req);
    idp.revoked.push(body.get("token"));
    res.writeHead(200);
    return res.end();
  }
  // /authorize is only ever a redirect target; the tests never fetch it
  send(404, { error: "not_found" });
}

function startIdp() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((req, res) => {
      handle(req, res).catch(() => {
        res.writeHead(500);
        res.end();
      });
    });
    server.once("error", reject);
    server.listen(idp.port, "127.0.0.1", () => {
      idp.port = server.address().port;
      idp.server = server;
      resolve();
    });
  });
}

function stopIdp() {
  return new Promise((resolve) => {
    idp.server.closeAllConnections();
    idp.server.close(() => resolve());
    idp.server = undefined;
  });
}

function resetIdp() {
  Object.assign(idp, {
    base: "",
    revocation: true,
    scopes: ["openid", "email", "profile", "offline_access"],
    claims: {},
    signWith: undefined,
    nonce: undefined,
    codeChallenge: undefined,
    tokenStatus: 200,
    tokenError: undefined,
    challenge: false,
    issueRefresh: true,
    idTokenOnRefresh: true,
    tokenBodies: [],
    tokenAuth: [],
    revoked: [],
  });
}

// ---------- driving the method ----------
function login(extra = {}) {
  return new OidcLogin({
    publicUrl: PUBLIC_URL,
    issuer: issuer(),
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    allowedEmails: ["Alice@Example.com"],
    allowedSubjects: [],
    groupsClaim: "groups",
    ...extra,
  });
}

function fakeRes() {
  const res = {
    headers: {},
    status: undefined,
    location: undefined,
    set(name, value) {
      res.headers[name.toLowerCase()] = value;
      return res;
    },
    redirect(status, location) {
      res.status = status;
      res.location = location;
      return res;
    },
  };
  return res;
}

let stateCounter = 0;
/** start() a login, hand its nonce and PKCE challenge to the mock as /authorize would, and return what came back. */
async function begin(method) {
  const loginState = `login-state-${++stateCounter}-${Math.random().toString(36).slice(2)}`;
  secrets.add(loginState);
  const res = fakeRes();
  await method.start(loginState, res);
  assert.equal(res.status, 302);
  const url = new URL(res.location);
  const nonce = url.searchParams.get("nonce");
  assert.ok(nonce, "a nonce is sent");
  secrets.add(nonce);
  idp.nonce = nonce;
  idp.codeChallenge = url.searchParams.get("code_challenge");
  return { loginState, url, res, nonce };
}

async function signIn(method) {
  const { loginState } = await begin(method);
  return method.finish({ query: { code: "c1", state: loginState } });
}

/** A signed-in upstream, for the recheck and cleanup tests. */
async function signedIn(method) {
  const r = await signIn(method);
  assert.ok("person" in r && !("refused" in r), JSON.stringify(r));
  return r.upstream;
}

await startIdp();

await check("start redirects to the provider with PKCE, state, nonce, scopes and extra params", async () => {
  resetIdp();
  const m = login({ authParams: "access_type=offline&prompt=consent" });
  const { url, loginState, res } = await begin(m);
  assert.equal(`${url.origin}${url.pathname}`, `${issuer()}/authorize`);
  const q = url.searchParams;
  assert.equal(q.get("response_type"), "code");
  assert.equal(q.get("client_id"), CLIENT_ID);
  assert.equal(q.get("redirect_uri"), "https://mcp.example.com/login/callback");
  assert.equal(q.get("code_challenge_method"), "S256");
  assert.ok(q.get("code_challenge"));
  assert.equal(q.get("state"), loginState);
  assert.ok(q.get("nonce"));
  const scopes = q.get("scope").split(" ");
  for (const s of ["openid", "email", "profile", "offline_access"]) assert.ok(scopes.includes(s), `scope ${s}`);
  assert.equal(q.get("access_type"), "offline");
  assert.equal(q.get("prompt"), "consent");
  assert.equal(res.headers["cache-control"], "no-store");

  // offline_access only where the provider lists it
  resetIdp();
  idp.scopes = ["openid", "email", "profile"];
  const plain = await begin(login());
  assert.deepEqual(plain.url.searchParams.get("scope").split(" ").sort(), ["email", "openid", "profile"]);
  assert.equal(plain.url.searchParams.get("prompt"), null);
});

await check("an allowed email that is verified signs in", async () => {
  resetIdp();
  const r = await signIn(login());
  assert.deepEqual(r.person, { id: "sub-alice", name: "Alice" });
  assert.equal(typeof r.upstream.refreshToken, "string");
  assert.equal(r.upstream.sub, "sub-alice");
  assert.equal(r.upstream.name, "Alice");
  assert.equal(typeof r.upstream.idTokenExpiresAt, "number");
  assert.ok(Math.abs(r.upstream.idTokenExpiresAt - (Date.now() + 3600_000)) < 10_000, "expiry in ms");

  const body = idp.tokenBodies.at(-1);
  assert.equal(body.get("grant_type"), "authorization_code");
  assert.ok(body.get("code_verifier"), "the PKCE verifier is sent");
  assert.equal(body.get("redirect_uri"), "https://mcp.example.com/login/callback");
  assert.ok(idp.tokenAuth.at(-1).startsWith("Basic "), "client_secret_basic is used");
  assert.deepEqual(idp.revoked, []);
});

await check("an issuer whose identifier ends in a slash signs in", async () => {
  resetIdp();
  idp.base = "/application/o/mcp/";
  assert.ok(issuer().endsWith("/application/o/mcp/"));
  const r = await signIn(login());
  assert.deepEqual(r.person, { id: "sub-alice", name: "Alice" });
  assert.equal(r.upstream.sub, "sub-alice");
});

await check("an allowed email that is not verified is refused", async () => {
  resetIdp();
  idp.claims = { email_verified: false };
  const r = await signIn(login());
  assert.equal(r.refused, "Alice is not allowed to use LubeLogger MCP.");
  assert.deepEqual(r.person, { id: "sub-alice", name: "Alice" });
  assert.equal(idp.revoked.length, 1, "the refused session is revoked");

  resetIdp();
  idp.claims = { email_verified: undefined };
  const r2 = await signIn(login());
  assert.equal(r2.refused, "Alice is not allowed to use LubeLogger MCP.");
  assert.deepEqual(r2.person, { id: "sub-alice", name: "Alice" });
});

await check("allowed by subject, allowed by group, and refused when none match", async () => {
  resetIdp();
  idp.claims = { sub: "sub-bob", name: "Bob", email: "bob@example.com" };
  const bySub = await signIn(login({ allowedEmails: [], allowedSubjects: ["sub-bob"] }));
  assert.deepEqual(bySub.person, { id: "sub-bob", name: "Bob" });

  resetIdp();
  idp.claims = { sub: "sub-bob", name: "Bob", email: "bob@example.com", groups: ["family", "lubelogger"] };
  const byGroup = await signIn(login({ allowedEmails: [], requiredGroup: "lubelogger" }));
  assert.deepEqual(byGroup.person, { id: "sub-bob", name: "Bob" });

  resetIdp();
  idp.claims = { sub: "sub-bob", name: "Bob", email: "bob@example.com", roles: ["lubelogger"] };
  const byRoles = await signIn(login({ allowedEmails: [], requiredGroup: "lubelogger", groupsClaim: "roles" }));
  assert.deepEqual(byRoles.person, { id: "sub-bob", name: "Bob" });

  // the group in the wrong claim, or as a string rather than a list, does not count
  resetIdp();
  idp.claims = { sub: "sub-bob", name: undefined, preferred_username: "bob", email: "bob@example.com", groups: "lubelogger" };
  const none = await signIn(login({ allowedSubjects: ["sub-carol"], requiredGroup: "lubelogger", groupsClaim: "groups" }));
  assert.equal(none.refused, "bob is not allowed to use LubeLogger MCP.");
  assert.deepEqual(none.person, { id: "sub-bob", name: "bob" });
  assert.equal(idp.revoked.length, 1);
});

await check("a token with the wrong issuer, audience, nonce or signature is refused as a failed login", async () => {
  const cases = [
    ["issuer", () => (idp.claims = { iss: "http://idp.example.com" })],
    ["audience", () => (idp.claims = { aud: "someone-else" })],
    ["nonce", () => (idp.claims = { nonce: "not-the-nonce" })],
    ["signature", () => (idp.signWith = otherKey.privateKey)],
    ["missing nonce", () => (idp.claims = { nonce: undefined })],
  ];
  for (const [what, setup] of cases) {
    resetIdp();
    setup();
    const m = login();
    const { loginState } = await begin(m);
    await throws(() => m.finish({ query: { code: "c1", state: loginState } }), what);
  }
});

await check("finish with an unknown or reused state throws", async () => {
  resetIdp();
  const m = login();
  const unknown = await throws(() => m.finish({ query: { code: "c1", state: "never-issued" } }));
  assert.equal(unknown.message, "unknown or expired sign-in");

  const { loginState } = await begin(m);
  const first = await m.finish({ query: { code: "c1", state: loginState } });
  assert.ok("person" in first);
  const again = await throws(() => m.finish({ query: { code: "c1", state: loginState } }));
  assert.equal(again.message, "unknown or expired sign-in");

  // a state older than 10 minutes is gone
  let t = Date.now();
  const timed = login({ now: () => t });
  const late = await begin(timed);
  t += 11 * MINUTE;
  await throws(() => timed.finish({ query: { code: "c1", state: late.loginState } }));
});

await check("recheck refreshes and re-applies the allowlist", async () => {
  resetIdp();
  const m = login();
  const upstream = await signedIn(m);

  const r = await m.recheck(upstream);
  assert.equal(r.ok, true, JSON.stringify(r));
  assert.deepEqual(r.person, { id: "sub-alice", name: "Alice" });
  assert.equal(r.upstream.sub, "sub-alice");
  assert.notEqual(r.upstream.refreshToken, upstream.refreshToken, "the rotated refresh token is kept");
  const body = idp.tokenBodies.at(-1);
  assert.equal(body.get("grant_type"), "refresh_token");
  assert.equal(body.get("refresh_token"), upstream.refreshToken);

  // a provider that doesn't rotate: the same refresh token stays
  idp.issueRefresh = false;
  const same = await m.recheck(r.upstream);
  assert.equal(same.ok, true);
  assert.equal(same.upstream.refreshToken, r.upstream.refreshToken);
  idp.issueRefresh = true;

  // the email is no longer allowed
  idp.claims = { email: "alice@elsewhere.example.com" };
  assert.deepEqual(await m.recheck(r.upstream), { ok: false, reason: "refused" });

  // a different subject in the refreshed token is never accepted
  idp.claims = { sub: "sub-carol" };
  assert.deepEqual(await m.recheck(r.upstream), { ok: false, reason: "refused" });
  idp.claims = {};

  // no new ID token: ok while the old one is valid, with its expiry kept
  idp.idTokenOnRefresh = false;
  const kept = await m.recheck(r.upstream);
  assert.equal(kept.ok, true);
  assert.equal(kept.upstream.idTokenExpiresAt, r.upstream.idTokenExpiresAt);
  assert.deepEqual(kept.person, { id: "sub-alice", name: "Alice" });
  idp.idTokenOnRefresh = true;

  idp.tokenStatus = 400;
  idp.tokenError = "invalid_grant";
  assert.deepEqual(await m.recheck(r.upstream), { ok: false, reason: "refused" });

  idp.tokenStatus = 403;
  idp.tokenError = "access_denied";
  assert.deepEqual(await m.recheck(r.upstream), { ok: false, reason: "refused" });

  // trouble with this server's own credentials, or with the provider, is never a verdict on the person
  for (const [status, error] of [
    [401, "invalid_client"],
    [400, "invalid_client"],
    [400, "unauthorized_client"],
    [401, undefined],
    [429, undefined],
    [503, undefined],
    [500, "server_error"],
  ]) {
    idp.tokenStatus = status;
    idp.tokenError = error;
    assert.deepEqual(await m.recheck(r.upstream), { ok: false, reason: "unavailable" }, `${status} ${error}`);
  }
  idp.tokenStatus = 200;
  idp.tokenError = undefined;

  // a 401 with a WWW-Authenticate challenge
  idp.challenge = true;
  assert.deepEqual(await m.recheck(r.upstream), { ok: false, reason: "unavailable" });
  idp.challenge = false;

  await stopIdp();
  assert.deepEqual(await m.recheck(r.upstream), { ok: false, reason: "unavailable" });
  await startIdp();
});

await check("without a refresh token, recheck is ok until the ID token expires, then refused", async () => {
  resetIdp();
  idp.issueRefresh = false;
  let t = Date.now();
  const m = login({ now: () => t });
  const upstream = await signedIn(m);
  assert.equal(upstream.refreshToken, undefined);

  const r = await m.recheck(upstream);
  assert.deepEqual(r, { ok: true, upstream, person: { id: "sub-alice", name: "Alice" } });
  assert.equal(idp.tokenBodies.length, 1, "no refresh is attempted");

  t = upstream.idTokenExpiresAt + 1;
  assert.deepEqual(await m.recheck(upstream), { ok: false, reason: "refused" });

  // and with a refresh token but no new ID token, past the expiry is refused too
  resetIdp();
  const m2 = login({ now: () => t });
  t = Date.now();
  const up2 = await signedIn(m2);
  idp.idTokenOnRefresh = false;
  t = up2.idTokenExpiresAt + 1;
  assert.deepEqual(await m2.recheck(up2), { ok: false, reason: "refused" });

  // an upstream with no subject is never ok
  assert.deepEqual(await m.recheck({}), { ok: false, reason: "refused" });
});

await check("cleanup revokes the refresh token when the provider has a revocation endpoint, and is quiet when it has none", async () => {
  resetIdp();
  const m = login();
  const upstream = await signedIn(m);
  await m.cleanup(upstream);
  assert.deepEqual(idp.revoked, [upstream.refreshToken]);

  // nothing to revoke
  await m.cleanup({ sub: "sub-alice", idTokenExpiresAt: Date.now() });
  assert.equal(idp.revoked.length, 1);

  resetIdp();
  idp.revocation = false;
  const noRevoke = login();
  const up2 = await signedIn(noRevoke);
  await noRevoke.cleanup(up2);
  assert.deepEqual(idp.revoked, []);
});

await check("discovery failing at first use is unavailable, and works once the provider is back", async () => {
  resetIdp();
  await stopIdp();
  const m = login();
  assert.deepEqual(await m.recheck({ sub: "sub-alice", name: "Alice", refreshToken: "rt-x", idTokenExpiresAt: Date.now() + MINUTE }), {
    ok: false,
    reason: "unavailable",
  });
  await throws(() => m.start("login-state-down", fakeRes()));

  await startIdp();
  const r = await signIn(m);
  assert.deepEqual(r.person, { id: "sub-alice", name: "Alice" });
});

await check("an http issuer other than localhost is refused at construction", async () => {
  await throws(async () => login({ issuer: "http://idp.example.com" }));
  login({ issuer: "https://idp.example.com" });
  login({ issuer: "http://localhost:9999" });
});

await check("nothing secret is ever in an error message", async () => {
  assert.ok(messages.length >= 8, `collected ${messages.length} messages`);
  for (const m of messages) for (const s of secrets) assert.ok(!m.includes(s), `a secret appears in: ${m}`);
});

await stopIdp();
if (failed) {
  process.stderr.write(`${failed} check(s) failed\n`);
  process.exit(1);
}
