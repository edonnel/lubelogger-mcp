# Sign-in Chooser, Step 2 (OpenID Connect) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add OpenID Connect as a second sign-in method: one named button on the sign-in screen, an allowlist, re-checks on refresh, and cleanup. This also picks up the two items step 1 deferred.

**Architecture:** A new `OidcLogin` implements the existing `LoginMethod` interface on top of `openid-client`, which handles the protocol (discovery, PKCE, state, nonce, ID token validation, refresh, revocation). Config gains the `OIDC_*` settings and makes `oidc` available. The app builds methods that are switched off but still configured, and passes them to the provider for cleanup only. The add-on gets an `oidc` checkbox and options.

**Tech Stack:** TypeScript on Node ≥ 22.4, Express 5, `@modelcontextprotocol/sdk` 1.32.1, zod 4, and the new dependency `openid-client` pinned to exactly `6.8.8`. Tests are plain `node:assert` scripts run by `npm test`.

**Spec:**
- `docs/superpowers/specs/2026-11-04-oauth-design.md`: the "OpenID Connect" method and the shared core.
- `docs/superpowers/specs/2026-11-05-signin-chooser-design.md`: the sign-in screen and connections, plus its "Carried into step 2" section.

Read both. Where they differ, the newer chooser design wins.

## Calls made in this plan (not in the specs)

These are mine; the owner reviews them with the plan.

- **Library:** `openid-client` 6.8.8, from the author of `jose`. Its dependencies are `jose` and `oauth4webapi`, and `npm audit` reports 0 vulnerabilities. The OAuth design's anti-goal forbids hand-rolled protocol code, and ID-token signature checks are exactly what not to hand-roll. 6.8.8 is the newest 6.x older than two weeks; 6.8.9 came out on 2026-11-02.
- **Discovery is lazy and cached.** The provider's discovery document is fetched on the first sign-in or refresh, not at startup. A failure counts as "unavailable": the screen's button shows the "try again shortly" page, and a refresh gets a 503. So an identity provider that is down never stops the server from starting.
- **`OIDC_AUTH_PARAMS`** is an optional query string added to the authorization request, e.g. `access_type=offline&prompt=consent` for Google. Google issues refresh tokens only that way, and without one a connection ends when the ID token expires (about an hour).
- **`OIDC_CLIENT_SECRET` is optional.** With it, the client authenticates with `client_secret_basic`. Without it, the client is public and relies on PKCE alone, which some self-hosted providers allow.
- **Identity:** `person.id` is the `sub` claim. `person.name` is the first present of `name`, `preferred_username`, `email` and `sub`.

## Global Constraints

- Match each file's existing style: 2-space TypeScript in `src/`, 2-space ESM in `test/*.mjs`, tabs and `snake_case` helpers in `home-assistant/lubelogger_mcp/launch.mjs`.
- `openid-client` is the only new runtime dependency. Pin it exactly as `"openid-client": "6.8.8"`, with no caret. No other new dependencies.
- Never write a token, code, login state, nonce, PKCE verifier, client secret, key or password to a log or a page. Names in logs go through `who()` or `JSON.stringify`.
- The sign-in screen needs no JavaScript and keeps the headers in `PAGE_HEADERS` exactly as they are.
- The `lm_login` cookie, the Origin check and the single-use login state apply to OIDC exactly as to Home Assistant.
- Method names are exactly `homeassistant`, `oidc`, `lubelogger-password` and `lubelogger-key`. After this step `homeassistant` and `oidc` are available. The other two still refuse with "is not available in this version".
- Messages for OIDC's "unavailable" cases go through the existing paths: a 503 `temporarily_unavailable` on refresh, and the existing "Login failed" pages on sign-in.
- Test data is fictional only (alice, bob, carol; `example.com`, `idp.example.com`).
- Commit messages are an imperative subject of 50 characters or fewer, with no AI attribution, and never `--no-verify`.
- `npm test` must pass at the end of every task.

## Review Focus

Each of these has a test in the task that owns it.

1. **An ID token from the wrong issuer or audience, with a bad signature, or with the wrong nonce** must be refused at sign-in. Never trust a token just because the token endpoint returned it. Owned by Task 2.
2. **An `email` on the allowlist with `email_verified` false, or missing,** must be refused. Owned by Task 2.
3. **A provider that issues no refresh token:** the connection works until the ID token expires, then the refresh is a definite refusal (not a 503), so Claude asks the person to sign in again. Owned by Task 2.
4. **The identity provider is down at startup, then comes back:** the server starts, and the first sign-in after the provider recovers works without a restart. Owned by Task 2 (lazy discovery) and Task 3 (startup).
5. **A server with both methods on:** a person signed in through Home Assistant and through OIDC as the same human gets two connections, and neither replaces the other. Owned by Task 3.

---

### Task 1: OIDC settings in config

**Files:**
- Modify: `src/config.ts`
- Test: `test/auth-config.mjs`

**Interfaces:**
- Consumes: `MethodName`, `METHOD_NAMES` and `Config.AUTH_METHODS` (already in `src/config.ts`).
- Produces, on `Config`, all optional:
  - `OIDC_ISSUER?: string`
  - `OIDC_CLIENT_ID?: string`
  - `OIDC_CLIENT_SECRET?: string`
  - `OIDC_DISPLAY_NAME: string`, defaulting to `"single sign-on"`
  - `OIDC_ALLOWED_EMAILS: string[]`, `OIDC_ALLOWED_SUBJECTS: string[]`
  - `OIDC_REQUIRED_GROUP?: string`
  - `OIDC_GROUPS_CLAIM: string`, defaulting to `"groups"`
  - `OIDC_AUTH_PARAMS?: string`

  The list settings are split on commas and trimmed, with empty entries dropped. `oidc` joins the available methods.

- [ ] **Step 1: Write the failing tests** in `test/auth-config.mjs`. `oidc` is `{ ...base, PUBLIC_URL: "https://mcp.example.com", OIDC_ISSUER: "https://idp.example.com/realms/home", OIDC_CLIENT_ID: "lubelogger-mcp", OIDC_ALLOWED_EMAILS: "alice@example.com" }`.

```js
await check("AUTH_METHODS=oidc with an issuer, client and allowlist starts", () => {
  const r = validateConfig({ ...oidc, AUTH_METHODS: "oidc" });
  assert.ok(r.ok, JSON.stringify(r.problems));
  assert.deepEqual(r.config.AUTH_METHODS, ["oidc"]);
  assert.deepEqual(r.config.OIDC_ALLOWED_EMAILS, ["alice@example.com"]);
  assert.equal(r.config.OIDC_DISPLAY_NAME, "single sign-on");
  assert.equal(r.config.OIDC_GROUPS_CLAIM, "groups");
});
await check("both methods together start, in the order given", () => {
  const r = validateConfig({ ...ha, ...oidc, AUTH_METHODS: "oidc,homeassistant" });
  assert.deepEqual(r.config.AUTH_METHODS, ["oidc", "homeassistant"]);
});
await check("oidc without an allowlist refuses to start", () => {
  const r = validateConfig({ ...oidc, OIDC_ALLOWED_EMAILS: undefined, AUTH_METHODS: "oidc" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => /OIDC_ALLOWED_EMAILS, OIDC_ALLOWED_SUBJECTS or OIDC_REQUIRED_GROUP/.test(p)));
});
await check("oidc names each missing setting", () => {
  const r = validateConfig({ ...base, PUBLIC_URL: "https://mcp.example.com", OIDC_ALLOWED_SUBJECTS: "abc", AUTH_METHODS: "oidc" });
  for (const name of ["OIDC_ISSUER", "OIDC_CLIENT_ID"])
    assert.ok(r.problems.some((p) => p.startsWith(name) && /oidc sign-in method/.test(p)), name);
});
await check("an issuer must be https, except on localhost", () => {
  assert.equal(validateConfig({ ...oidc, OIDC_ISSUER: "http://idp.example.com", AUTH_METHODS: "oidc" }).ok, false);
  assert.ok(validateConfig({ ...oidc, OIDC_ISSUER: "http://localhost:9000/realms/home", AUTH_METHODS: "oidc" }).ok);
  assert.ok(validateConfig({ ...oidc, OIDC_ISSUER: "http://127.0.0.1:9000", AUTH_METHODS: "oidc" }).ok);
});
await check("lubelogger methods still refuse to start", () => {
  const r = validateConfig({ ...ha, AUTH_METHODS: "homeassistant,lubelogger-key" });
  assert.ok(r.problems.some((p) => /lubelogger-key.*not available in this version/.test(p)));
});
await check("no OIDC setting value appears in any problem", () => {
  const r = validateConfig({ ...oidc, OIDC_CLIENT_SECRET: "SECRET-PLANTED-31", OIDC_ISSUER: "not a url", AUTH_METHODS: "oidc" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.every((p) => !p.includes("SECRET-PLANTED-31")));
});
```

- [ ] **Step 2: Run `npm test`.** Expected: the new checks FAIL.

- [ ] **Step 3: Implement in `src/config.ts`.**
  - Add `"oidc"` to `AVAILABLE_METHODS`. The `AUTH_MODE` wording follows the list, e.g. "use token, homeassistant or oidc".
  - Add the settings with the defaults in Interfaces.
  - `OIDC_ISSUER` is a URL kept as given apart from trailing slashes. It may have a path, since issuers often do. It must be `https:`, or `http:` with host `localhost` or `127.0.0.1`.
  - When `oidc` is on, these problems apply:
    - `OIDC_ISSUER` and `OIDC_CLIENT_ID` are required, with the message `is required when the oidc sign-in method is on`;
    - at least one allowlist entry must exist, reported on `OIDC_ALLOWED_EMAILS` as `at least one of OIDC_ALLOWED_EMAILS, OIDC_ALLOWED_SUBJECTS or OIDC_REQUIRED_GROUP is required when the oidc sign-in method is on`.
  - When `oidc` is off, its settings are still validated for format when present, because Task 3 builds a switched-off method from them for cleanup. They are never required then.

- [ ] **Step 4: Run `npm test`.** Expected: PASS.

- [ ] **Step 5: Commit**, as "Add OpenID Connect settings".

---

### Task 2: The `OidcLogin` method

**Files:**
- Create: `src/auth/oidc.ts`
- Create: `test/oidc.mjs`, and add `node test/oidc.mjs` to the `test` script in `package.json`, after `auth-store`.
- Modify: `package.json` and `package-lock.json`, adding `"openid-client": "6.8.8"` with `npm install --save-exact openid-client@6.8.8`.

**Interfaces:**
- Consumes: `LoginMethod` and `RecheckResult` (`src/auth/login-method.ts`), and `Person` (`src/auth/store.ts`).
- Produces:

```ts
export type OidcOptions = {
  publicUrl: string;            // redirect URI is `${publicUrl}/login/callback`
  issuer: string;
  clientId: string;
  clientSecret?: string;
  allowedEmails: readonly string[];
  allowedSubjects: readonly string[];
  requiredGroup?: string;
  groupsClaim: string;
  authParams?: string;          // extra authorization query, e.g. "access_type=offline&prompt=consent"
  now?: () => number;
};
export class OidcLogin implements LoginMethod { constructor(opts: OidcOptions); }
```

The upstream it stores is `{ sub: string; refreshToken?: string; idTokenExpiresAt: number }`. `idTokenExpiresAt` is in milliseconds.

- [ ] **Step 1: Write the failing tests** in `test/oidc.mjs`, against a mock identity provider on `node:http`.
  - The mock serves `/.well-known/openid-configuration`, a JWKS endpoint, `/authorize` (never fetched by the tests), `/token` and `/revoke`.
  - It signs ID tokens RS256 with a key pair from `crypto.generateKeyPairSync("rsa", { modulusLength: 2048 })`. Export its public key as a JWK for the JWKS.
  - Each test sets the claims the next token answer carries.
  - The mock listens on `127.0.0.1` over http, which the method accepts because config does (see Step 3).
  - Drive the method directly: call `start(loginState, res)` with a fake `res` that captures the redirect, read `state`, `nonce` and `code_challenge` from that URL, then call `finish(req)` with `req.query = { code: "c1", state }`.

  Write these checks in full:
  - **"start redirects to the provider with PKCE, state, nonce, scopes and extra params".**
    - The redirect URL's origin and path are the discovery document's `authorization_endpoint`.
    - `response_type=code`, `client_id`, and `redirect_uri=https://mcp.example.com/login/callback`.
    - `code_challenge_method=S256`, and `state` equals the `loginState` passed in.
    - A `nonce` is present.
    - `scope` has `openid email profile`, plus `offline_access` when the mock lists it in `scopes_supported`.
    - With `authParams: "access_type=offline&prompt=consent"`, both parameters appear.
  - **"an allowed email that is verified signs in"**: `finish` returns `person { id: sub, name }` and the upstream above. The mock's `/token` received the PKCE `code_verifier` and `grant_type=authorization_code`.
  - **"an allowed email that is not verified is refused"**: `email_verified: false`, and separately with it missing. The result has `refused`, with `person` set.
  - **"allowed by subject, allowed by group, and refused when none match"**: `requiredGroup: "lubelogger"` with `groups: ["lubelogger"]`. Also a custom `groupsClaim: "roles"`.
  - **"a token with the wrong issuer, audience, nonce or signature is refused as a failed login"**: each case makes `finish` throw. The provider turns a throw into "Login failed". Signature: sign with a second key that isn't in the JWKS.
  - **"finish with an unknown or reused state throws"**: a state that `start` never issued, or one already used once.
  - **"recheck refreshes and re-applies the allowlist"**:
    - the mock's refresh answer gives a new refresh token and ID token, and the result is `ok` with the rotated `refreshToken`;
    - when the new token's email is no longer allowed, the result is `refused`;
    - `/token` answering 400 `invalid_grant` gives `refused`;
    - `/token` answering 503, or the mock stopped, gives `unavailable`.
  - **"without a refresh token, recheck is ok until the ID token expires, then refused"**: use the `now` option to move past `idTokenExpiresAt`.
  - **"cleanup revokes the refresh token when the provider has a revocation endpoint, and is quiet when it has none"**.
  - **"discovery failing at first use is unavailable, and works once the provider is back"**:
    - with the mock down, `recheck` gives `unavailable` and `start` throws;
    - restart the mock on the same port, and `start` then works without a new `OidcLogin`.
  - **"nothing secret is ever in an error message"**: collect every thrown error message from the checks above and assert that none contains the client secret, a code, a token or the nonce.

- [ ] **Step 2: Run `npm run build && node test/oidc.mjs`.** Expected: FAIL, because `dist/auth/oidc.js` doesn't exist yet.

- [ ] **Step 3: Implement `src/auth/oidc.ts`** with `openid-client` 6.8.8.
  - **Discovery:** `discovery(new URL(issuer), clientId, clientSecret ? { client_secret } : undefined, clientSecret ? ClientSecretBasic(secret) : None(), insecure ? { execute: [allowInsecureRequests] } : undefined)`.
    - `insecure` is true exactly when the issuer is `http:` on `localhost` or `127.0.0.1`. Those are the only http issuers config accepts.
    - Also throw in the constructor for any other `http:` issuer, so the method never relies on config alone. Cache the configuration promise, and clear the cache when it rejects so the next call retries.
  - **`start`:** create a code verifier and a nonce. Keep `{ verifier, nonce, createdAt }` in a `Map` keyed by `loginState`, entries expiring after 10 minutes, and sweep it on each call. Redirect to `buildAuthorizationUrl(...)` with `state: loginState`, plus the parsed `authParams`.
  - **`finish`:** take the map entry for `req.query.state` (delete it, so it is single use). A missing entry throws `Error("unknown or expired sign-in")`. Then:
    - call `authorizationCodeGrant(config, currentUrl, { pkceCodeVerifier, expectedNonce, expectedState: loginState, idTokenExpected: true })`, where `currentUrl` is the redirect URI plus `req.query`'s own search string;
    - take the claims from `tokens.claims()`;
    - apply the allowlist.
  - **Allowlist:** allowed when any of these holds:
    - the `email` is listed (case-insensitive) and `email_verified === true`;
    - the `sub` is listed;
    - `requiredGroup` is set and `claims[groupsClaim]` is an array containing it.
  - **Refusal message:** `"<name> is not allowed to use LubeLogger MCP."`, returned with `person`. A refusal cleans up the session it created (it revokes the refresh token).
  - **`recheck`:**
    - with a refresh token, `refreshTokenGrant`, then re-apply the allowlist to the new ID token's claims. If no new ID token comes back, keep the old `sub` and claims. That is ok only while `idTokenExpiresAt` is still in the future, and then the result keeps the old expiry;
    - without a refresh token, the result is `ok` with the upstream unchanged until `idTokenExpiresAt`, and `refused` after;
    - classify failures: an `openid-client` `ResponseBodyError` with `error === "invalid_grant"` (or any 4xx) is `refused`, and anything else (a network error, a 5xx, discovery failing) is `unavailable`.
  - **`cleanup`:** if there is a refresh token and the configuration has a `revocation_endpoint`, call `tokenRevocation`. Any error is thrown for the provider to log.
  - Error messages never quote a token, code, nonce, verifier or secret. Messages from `openid-client` are kept only when they carry no response body. When unsure, map to a fixed message.

- [ ] **Step 4: Run `npm test`.** Expected: PASS, including the existing suites.

- [ ] **Step 5: Commit**, as "Add the OpenID Connect sign-in method".

---

### Task 3: Two methods on one server, and cleanup for switched-off methods

**Files:**
- Modify: `src/app.ts`, `src/auth/provider.ts`, `src/auth/signin-page.ts`
- Test: `test/oauth-ha.mjs`

**Interfaces:**
- Consumes: `OidcLogin` and `OidcOptions` (Task 2), and the `OIDC_*` config (Task 1).
- Produces:
  - **The `LoginProvider` constructor** takes a new option, `opts.retired?: ReadonlyMap<MethodName, LoginMethod>`. These are methods that are switched off but still configured, used only by cleanup. `safeCleanup` tries `methods` first, then `retired`. It logs "could not be revoked" only when neither has the method.
  - **`BUTTON_LABEL.oidc`** becomes a fallback. The provider's choices use `opts.labels?: Partial<Record<MethodName, string>>`, and `app.ts` passes `{ oidc: \`Continue with ${config.OIDC_DISPLAY_NAME}\` }`.
  - **`METHOD_ICON.oidc`** is a generic key icon in `signin-page.ts`, inline SVG using `currentColor`. No provider logos.
  - **`app.ts`:**
    - `buildLoginMethod` builds `oidc` from the config;
    - a new `buildRetiredMethods(config, publicUrl)` returns a method for each method that is off but configured: `homeassistant` when `HOME_ASSISTANT_URL` and `HOME_ASSISTANT_PUBLIC_URL` are set, and `oidc` when `OIDC_ISSUER` and `OIDC_CLIENT_ID` are set;
    - `AppDeps.retiredMethods?: Partial<Record<MethodName, LoginMethod>>` overrides those in tests.

- [ ] **Step 1: Write the failing tests** in `test/oauth-ha.mjs`. Use a second stub method, `stubOidc`, shaped like the file's existing `stub`, but whose `start` redirects to `/login/callback` with `as=<name>` and whose people have ids `oidc-<name>`. Build an app with `config({ AUTH_METHODS: "homeassistant,oidc", AUTH_MODE: undefined, OIDC_ISSUER: "https://idp.example.com", OIDC_CLIENT_ID: "x", OIDC_ALLOWED_SUBJECTS: "s", OIDC_DISPLAY_NAME: "Example ID" })` and `{ loginMethods: { homeassistant: stub, oidc: stubOidc } }`.

```js
await check("the screen shows both buttons, in config order, with the OIDC provider's name", async () => {
  const { html } = await openApproval(claude, "alice");
  const buttons = [...html.matchAll(/name="method" value="([^"]+)"/g)].map((m) => m[1]);
  assert.deepEqual(buttons, ["homeassistant", "oidc"]);
  assert.match(html, /Continue with Example ID<\/button>/);
});

await check("a login state locked to one method refuses a second", async () => {
  const { loginState, cookie } = await openApproval(claude, "alice");
  assert.equal((await approve(loginState, cookie, {}, "homeassistant")).status, 302);
  const second = await approve(loginState, cookie, {}, "oidc");
  assert.equal(second.status, 400);
  assert.match(await second.text(), /Login expired/);
  assert.equal(stubOidc.started, 0);
});

await check("the same person through both methods gets two connections, neither replaced", async () => {
  // sign in as alice through homeassistant, then through oidc, with the same client.
  // Both refresh tokens still refresh, and neither stub's cleanup ran.
});

await check("a switched-off method that is still configured has its upstream session revoked", async () => {
  // connect through oidc on the two-method app, then restart over the same DATA_DIR with only homeassistant on
  // and retiredMethods: { oidc: stubOidc }. Expire nothing; the startup purge ends the oidc connection,
  // stubOidc.cleaned grows by one, and no "could not be revoked" line is logged for it.
});

await check("with the identity provider down, the server still starts", async () => {
  // build the app with the real OidcLogin (no stub) pointing at an unused localhost port;
  // createApp resolves, /healthz is 200 and /authorize still shows the screen.
});
```

Write the three bodies left as comments in full, using the file's helpers. Each comment lists the assertions. `stubOidc.started` counts calls to `start`.

- [ ] **Step 2: Run `npm test`.** Expected: the new checks FAIL.

- [ ] **Step 3: Implement** as Interfaces says.
  - **`app.ts`:**
    - passes the OIDC options from config;
    - builds `retired` only for methods not in `AUTH_METHODS`;
    - builds no network connections at construction, since discovery is lazy.
  - **`provider.ts`:**
    - the labels option and the `retired` map, as in Interfaces;
    - the purge, the refresh path and `end` still treat a method that is only in `retired` as switched off. `retired` is for cleanup and nothing else.

- [ ] **Step 4: Run `npm test`.** Expected: PASS.

- [ ] **Step 5: Commit**, as "Run both sign-in methods on one server".

---

### Task 4: Add-on options for OIDC

**Files:**
- Modify: `home-assistant/lubelogger_mcp/launch.mjs`, `home-assistant/lubelogger_mcp/config.yaml`
- Test: `test/auth-config.mjs`

**Interfaces:**
- Consumes: the `OIDC_*` settings (Task 1).
- Produces:
  - `buildEnv` passes the OIDC options whenever they are set, whether `oidc` is on or off, so a switched-off method can still be cleaned up. The mapping: `oidc_issuer` → `OIDC_ISSUER`, `oidc_client_id`, `oidc_client_secret`, `oidc_display_name`, `oidc_allowed_emails`, `oidc_allowed_subjects`, `oidc_required_group`, `oidc_groups_claim`, `oidc_auth_params`.
  - `HOME_ASSISTANT_PUBLIC_URL` is passed whenever it is set, too.
  - `check_options` requires `public_url` whenever any method is on. When `oidc` is on, it also requires `oidc_issuer`, `oidc_client_id`, and at least one of the three allowlist options.

- [ ] **Step 1: Write the failing tests** next to the existing launcher checks.

```js
await check("the oidc checkbox adds oidc to AUTH_METHODS and passes its options", () => {
  const options = { ...addonOptions, oidc: true, oidc_issuer: "https://idp.example.com", oidc_client_id: "x", oidc_allowed_emails: "alice@example.com" };
  assert.deepEqual(check_options(options), []);
  const env = buildEnv(options);
  assert.equal(env.AUTH_METHODS, "homeassistant,oidc");
  assert.equal(env.OIDC_ISSUER, "https://idp.example.com");
  assert.ok(validateConfig(env).ok);
});
await check("oidc on without its settings names each one, never a value", () => {
  const problems = check_options({ ...addonOptions, oidc: true, oidc_client_secret: "SECRET-PLANTED-58" });
  for (const name of ["oidc_issuer", "oidc_client_id", "oidc_allowed_emails"]) assert.ok(problems.some((p) => p.includes(name)), name);
  assert.ok(problems.every((p) => !p.includes("SECRET-PLANTED-58")));
});
await check("oidc alone still requires public_url", () => {
  const options = { lubelogger_url: "http://lubelogger:8080", lubelogger_api_key: "k", homeassistant: false, oidc: true, oidc_issuer: "https://idp.example.com", oidc_client_id: "x", oidc_allowed_subjects: "s" };
  assert.ok(check_options(options).some((p) => /public_url/.test(p)));
});
await check("a switched-off oidc keeps its settings in the environment for cleanup", () => {
  const env = buildEnv({ ...addonOptions, oidc: false, oidc_issuer: "https://idp.example.com", oidc_client_id: "x" });
  assert.equal(env.AUTH_METHODS, "homeassistant");
  assert.equal(env.OIDC_ISSUER, "https://idp.example.com");
});
```

- [ ] **Step 2: Run `npm test`.** Expected: FAIL.

- [ ] **Step 3: Implement.**
  - **`launch.mjs`:** `enabled_methods` reads `oidc === true`. The OIDC checkbox defaults off, so only an explicit `true` turns it on, unlike `homeassistant`.
  - **`config.yaml`:**
    - add `oidc: false` under `options`;
    - in `schema`, add `oidc: bool?`, `oidc_issuer: url?`, `oidc_client_id: str?`, `oidc_client_secret: password?`, `oidc_display_name: str?`, `oidc_allowed_emails: str?`, `oidc_allowed_subjects: str?`, `oidc_required_group: str?`, `oidc_groups_claim: str?` and `oidc_auth_params: str?`;
    - leave `version` for Task 6.

- [ ] **Step 4: Run `npm test`.** Expected: PASS.

- [ ] **Step 5: Commit**, as "Add OpenID Connect options to the add-on".

---

### Task 5: Documentation

**Files:**
- Modify: `README.md`, `.env.example`, `docs/superpowers/specs/2026-11-05-signin-chooser-design.md`

- [ ] **Step 1: Update `README.md`.**
  - Add a "Sign in with OpenID Connect" section with:
    - the settings table;
    - registering the client at the provider: redirect URI `https://mcp.example.com/login/callback`, confidential or public;
    - that a provider which issues no refresh token ends the connection within the hour, and the Google `OIDC_AUTH_PARAMS` example;
    - the allowlist rules, including that `email` needs `email_verified`.
  - Update "Changes from upstream" and the methods list in the configuration table.
  - Update the "Switching a method off" paragraph: a switched-off method that is still configured has its upstream sessions revoked; one whose settings are gone does not.
  - In "Lock it down with Cloudflare", note that the OIDC provider is called by the server, not the browser, so it needs no exception.
- [ ] **Step 2: Update `.env.example`.** Add an OIDC block, commented out, one comment line above each variable.
- [ ] **Step 3: Close the step 2 carry-overs.** In the chooser design's "Carried into step 2" section, mark both items done, naming the tests that cover them.
- [ ] **Step 4: Check the docs.** Run `npm test`. Expected: PASS. Also grep the README for `not available in this version` and check it names only the LubeLogger methods.
- [ ] **Step 5: Commit**, as "Document OpenID Connect sign-in".

---

### Task 6: Pin the add-on (controller, after the final review)

- [ ] **Step 1: Pin the build.** In `Dockerfile`, set `ARG REF=` to the full SHA of the last reviewed commit. In `config.yaml`, set `version: "0.6.0-<first 7 of that SHA>"`.
- [ ] **Step 2: Run `npm test`.** Expected: PASS.
- [ ] **Step 3: Commit**, as "Pin the add-on to the OpenID Connect build".
- [ ] **Step 4: Ask the owner before merging, pushing or deploying.** The deploy check:
  - the add-on updates with no settings changed and `oidc` off;
  - the sign-in screen still shows only the Home Assistant button;
  - the existing connection keeps working.

  Trying OIDC live needs an identity provider the owner chooses, so it is a separate step for the owner.
