# Sign-in Follow-ups Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Clear the review follow-ups left after steps 2 and 3 of the sign-in chooser, none of which lets anyone in, so the methods fail more accurately and the code and docs are tidier.

**Architecture:** Small, contained fixes in the existing files: `oidc.ts` and `config.ts` for OpenID Connect, `lubelogger-login.ts` and `lubelogger.ts` for the LubeLogger methods, `provider.ts` for purging and lockout messages, then a pure refactor that moves the form path out of `provider.ts`, and last the launcher and docs. No new dependencies and no new configuration.

**Tech Stack:** TypeScript (Node 20+), Express, `@modelcontextprotocol/sdk` 1.32.1, `openid-client` 6.8.8, zod; tests are plain `node:assert` scripts under `test/`, run by `npm test` after a build.

**Spec:** `docs/superpowers/specs/2026-11-05-signin-chooser-design.md`, sections "Follow-ups after step 2" and "Follow-ups after step 3". The approved `docs/superpowers/specs/2026-11-04-oauth-design.md` stays the authority for everything else.

## Global Constraints

- Every anti-goal of both design docs still holds: no way in through a switched-off method, no secrets (password, key, token, code) in a page, a log line or an error message, no JavaScript on the sign-in screen, no looser CSP.
- `openid-client` stays pinned at exactly `6.8.8`.
- Tests use fictional data only (`example.com`, alice, bob); never a real name, host or address.
- TypeScript is indented with 2 spaces and uses double quotes, matching the existing files (the project's style wins over the global defaults).
- Each task ends with `npm test` passing in full.
- Commit messages: imperative subject of 50 characters or less, no AI attribution.

## Review Focus

1. A LubeLogger behind a proxy that answers 404 or 429 for `/api/whoami`: the person should see "can't be reached", not "wrong password", and a key connection must not end on refresh. Test in Task 2.
2. An API key pasted with a trailing newline or a non-ASCII character: the person should see "That API key is not valid.", not "can't be reached". Test in Task 2.
3. An OIDC provider whose refreshed ID token drops the `name` claim: the person's name must not change to their subject ID. Test in Task 1.
4. A server restarting with several connections from a switched-off OIDC method whose provider drops packets: startup must not wait on each cleanup. Test in Task 3.
5. An add-on option holding only spaces: it must count as unset in the launcher's check and in the environment it builds. Test in Task 5.

## Out of scope

- Refusing a credentialed whoami answer of `isRoot: true` (marked optional in the spec). It needs a decision about root users signing in with their own key, so it stays a follow-up.
- Username case folding in the limiter. Whether it differs from LubeLogger's lookup is unverified, and it stays a follow-up until it is.

---

### Task 1: OpenID Connect fixes

**Files:**
- Modify: `src/auth/oidc.ts`
- Modify: `src/config.ts` (the `OIDC_AUTH_PARAMS` check in `superRefine`)
- Test: `test/oidc.mjs`, `test/auth-config.mjs`, `test/oauth-ha.mjs`

**Interfaces:**
- Consumes: `OidcLogin`, `personFrom(claims, sub)`, `refreshVerdict`, `cleanup(upstream)` as they are today.
- Produces: `personFrom(claims: Claims, sub: string, fallbackName?: string): Person`; the exported constant `RESERVED_AUTH_PARAMS = ["client_id", "response_type", "response_mode", "request", "request_uri"] as const` in `src/config.ts`.

- [ ] **Step 1: Write the failing tests.** In `test/oidc.mjs`, using the file's existing mock provider and `check(name, fn)` helper:
  - `a refreshed ID token without a name keeps the stored name`: sign in as alice with `name: "Alice Example"`, refresh with an ID token holding only `sub` and `email_verified: false`; assert `result.person.name === "Alice Example"` and `result.upstream.name === "Alice Example"`.
  - `a refused refreshed ID token revokes the rotated refresh token`: the refresh returns a new refresh token and an ID token whose subject is no longer allowlisted; assert `reason === "refused"` and that the mock's revocation endpoint received the new refresh token exactly once.
  - `the ID token signature is checked on refresh`: the refresh returns an ID token signed with a key not in the JWKS; assert `{ ok: false }` and no throw.
  - `a provider that never answers times out as unavailable`: the token endpoint holds the request past the timeout (inject a short timeout through the existing test seam, or stub `fetch` the way the file already does); assert `reason === "unavailable"`.
  - `cleanup that throws is logged, not raised`: in `test/oauth-ha.mjs`, a stub method whose `cleanup` throws; ending its connection still removes it and the request succeeds.
  - In `test/auth-config.mjs`: `OIDC_AUTH_PARAMS may not set protocol parameters`: for each reserved name, `loadConfig` with `OIDC_AUTH_PARAMS=<name>=x` fails with a message naming `OIDC_AUTH_PARAMS` and that parameter; `OIDC_AUTH_PARAMS=access_type=offline&prompt=consent` still loads.
  - In `test/oauth-ha.mjs`: `markup in OIDC_DISPLAY_NAME is escaped on the button`: with display name `<b>Acme</b>`, the screen contains `Continue with &lt;b&gt;Acme&lt;/b&gt;` and no `<b>`.
  - In `test/oauth-ha.mjs`: `the real retired-method build revokes through OIDC`: build the server through `createApp` with `AUTH_METHODS=homeassistant` and full `OIDC_*` settings (no injected `retiredMethods`), seed an `oidc` connection, purge, and assert the mock provider saw one revocation.

- [ ] **Step 2: Run the tests and confirm the new ones fail.** Run: `npm test`. Expected: the new checks print `FAIL`, all others `ok`.

- [ ] **Step 3: Implement.**
  - `personFrom` takes `fallbackName`; `recheck` passes the stored `name` so the order is `name`, `preferred_username`, `email`, stored name, `sub`. `finish` passes nothing.
  - In `recheck`, when `claims.sub !== sub || !this.allowed(claims)` and the provider returned a new refresh token different from the old one, call `this.cleanup({ refreshToken: tokens.refresh_token })` inside a `try`/`catch` that swallows the error, then return refused.
  - Delete the unused `OidcRejected` class.
  - In `config.ts`, export `RESERVED_AUTH_PARAMS` and add an issue on path `OIDC_AUTH_PARAMS` for each reserved name present in `new URLSearchParams(value)`: message `must not set ${name} (the server sets it itself)`.

- [ ] **Step 4: Tidy the existing tests.** In `test/oauth-ha.mjs`, read `stubOidc.started` into a baseline at the start of each check that asserts on it and compare against `baseline + n`. In `test/oidc.mjs`, give the bad-token loop's assertion a message naming the case, e.g. `assert.equal(r.ok, false, \`case: ${label}\`)`.

- [ ] **Step 5: Run the tests and confirm they pass.** Run: `npm test`. Expected: every line `ok`, exit code 0.

- [ ] **Step 6: Commit.** Subject: `Tighten OpenID Connect refresh and settings`.

---

### Task 2: LubeLogger method fixes

**Files:**
- Modify: `src/auth/lubelogger-login.ts`
- Modify: `src/lubelogger.ts` (`LubeLoggerClient` constructor and its 401/403 hint)
- Modify: `src/app.ts` (`clientFor`)
- Test: `test/lubelogger-login.mjs`, `test/smoke.mjs` or `test/oauth-ha.mjs` (wherever the client's error text is already asserted)

**Interfaces:**
- Consumes: `identify`, `Whoami.ask`, `LubeLoggerKeyLogin.check`/`recheck`, `clientFor(auth)`.
- Produces: `new LubeLoggerClient(baseUrl: string, apiKey: string, timeoutMs: number, keySource?: "shared" | "connection")`, default `"shared"`.

- [ ] **Step 1: Write the failing tests** in `test/lubelogger-login.mjs`, extending the mock so a test can make `/api/whoami` answer a chosen status:
  - `only a 401 is a wrong password`: credentialed whoami answering 404, then 429, then 403; each `check` returns `{ unavailable: UNAVAILABLE }`, and a 401 still returns `{ invalid: WRONG_PASSWORD }`.
  - `a key connection survives a 404 or 429 on refresh`: `recheck` with whoami answering 404 or 429 returns `{ ok: false, reason: "unavailable" }`; with 401 it returns `reason: "refused"`.
  - `a key a header can't carry is not valid`: `check({ apiKey: "key\n" })` and `check({ apiKey: "clé" })` return `{ invalid: WRONG_KEY }` and the mock receives no request.
  - `a colon in the username is a wrong password without asking LubeLogger`: `check({ username: "al:ice", password: "x" })` returns `{ invalid: WRONG_PASSWORD }` and the mock receives no request.
  - `the probe succeeds but the credentialed call fails`: the no-credential probe answers 401 and the credentialed call fails at the network level; the result is `{ unavailable: UNAVAILABLE }`.
  - Client hint: a `LubeLoggerClient` built with `keySource: "connection"` that gets a 401 throws a message containing `your LubeLogger API key` and not `LUBELOGGER_API_KEY`; with the default it still names `LUBELOGGER_API_KEY`.

- [ ] **Step 2: Run the tests and confirm the new ones fail.** Run: `npm test`.

- [ ] **Step 3: Implement.**
  - `identify`: `401` → `{ rejected: true }`; every other non-200 → `{ unavailable: true }`. Update the doc comment.
  - `LubeLoggerKeyLogin.check` and `recheck`: before any request, a key that does not match `/^[\x21-\x7E]+$/` is `{ invalid: WRONG_KEY }` in `check` and `refused` in `recheck`.
  - `LubeLoggerClient`: the 401/403 hint is `" (check LUBELOGGER_API_KEY and that the key's role allows adding records: Editor or higher)"` for `"shared"` and `" (check that your LubeLogger API key still exists and that its role allows adding records: Editor or higher)"` for `"connection"`.
  - `clientFor` passes `"connection"` when it builds a client from the connection's own key.

- [ ] **Step 4: Run the tests and confirm they pass.** Run: `npm test`.

- [ ] **Step 5: Commit.** Subject: `Treat only a 401 as rejected LubeLogger sign-in`.

---

### Task 3: Purge without waiting, and accurate lockout messages

**Files:**
- Modify: `src/auth/provider.ts` (`purgeOnce`, `end`, the lockout branch of `checkForm`)
- Test: `test/oauth-ha.mjs`

**Interfaces:**
- Consumes: `FailureLimiter.lockedFor(keys)`, `failureCount(key)`, `MAX_FAILURES`, `WINDOW_MS`.
- Produces: `end(connection, why, opts?: { awaitCleanup?: boolean })`, default `true`; the exported constant `STILL_CHECKING = "A sign-in is still being checked. Try again in a moment."`.

- [ ] **Step 1: Write the failing tests** in `test/oauth-ha.mjs`:
  - `startup does not wait on a switched-off method's cleanup`: three connections from a retired stub whose `cleanup` never resolves; `startPurging()` resolves within 1 s, the connections are gone from the store, and the stub saw three cleanup calls.
  - `a refusal caused only by attempts in flight says so`: hold five password checks open (a stub whose `check` waits on a promise the test resolves), post a sixth; it answers 429 with `STILL_CHECKING`, not a minute count.
  - `the wait shown is when the key is free`: with six failures counted (the in-flight overshoot case), the message's minute count equals `Math.ceil` of the time until fewer than `MAX_FAILURES` failures remain in the window, checked by advancing `now` to that moment and seeing the next post let in.
  - Tighten the existing concurrency check to `assert.equal(stubPassword.checks, 5)` (it allows fewer today).
  - `a post that loses the state while LubeLogger is asked gets the expired page`: two password posts with the same `loginState` held open together; release both; exactly one completes the login, the other gets 400 `Login expired`, and the loser's upstream is cleaned up once.
  - In the token-mode key test, assert the configuration problem it expects (the message naming `LUBELOGGER_API_KEY`), not only that loading failed.

- [ ] **Step 2: Run the tests and confirm the new ones fail.** Run: `npm test`.

- [ ] **Step 3: Implement.**
  - `end` with `awaitCleanup: false` starts `safeCleanup` with `void` and logs the disconnect right away. `purgeOnce` passes `{ awaitCleanup: false }` for `METHOD_OFF` only; expired connections keep awaiting.
  - In `checkForm`: if `wait > 0`, show `Too many attempts. Try again in ${Math.ceil(wait / 60_000)} minutes.`; if only `busy` is true, show `STILL_CHECKING` with status 429.
  - If the six-failure test shows `lockedFor` overstating, correct it in `rate-limit.ts` so the wait is until the count drops below `MAX_FAILURES`, and add the matching check to `test/rate-limit.mjs`.

- [ ] **Step 4: Run the tests and confirm they pass.** Run: `npm test`.

- [ ] **Step 5: Commit.** Subject: `Purge without waiting and fix lockout wording`.

---

### Task 4: Move the form sign-in path out of the provider

**Files:**
- Create: `src/auth/form-login.ts`
- Modify: `src/auth/provider.ts`
- Test: no new tests; the whole existing suite is the check.

**Interfaces:**
- Consumes: everything `checkForm` uses today: `FailureLimiter`, `addressKey`, `MAX_KEY_LENGTH`, `MAX_FAILURES`, `STILL_CHECKING`, the in-flight map, `showScreen`, `page`, `safeCleanup`, `completeLogin`.
- Produces: `class FormLoginGate` in `src/auth/form-login.ts` with `constructor(limiter: FailureLimiter)` and `async attempt(req: express.Request, method: FormLoginMethod): Promise<{ fields: FormFields; username?: string; outcome: FormCheckResult | { locked: string } | { failed: true } }>`. It owns the field reading, the key building, the in-flight count and the limiter calls. `provider.ts` keeps the state checks, the page responses and `completeLogin`.

- [ ] **Step 1: Move the code.** Behaviour must not change: same status codes, messages, log lines and order of checks. The "no await between the in-flight release and the failure record" rule stays inside `attempt`.

- [ ] **Step 2: Run the tests.** Run: `npm test`. Expected: every line `ok`, with no test edited.

- [ ] **Step 3: Check the size.** Run: `wc -l src/auth/provider.ts src/auth/form-login.ts`. Expected: `provider.ts` under 650 lines.

- [ ] **Step 4: Commit.** Subject: `Move the form sign-in path to its own module`.

---

### Task 5: Launcher and docs polish

**Files:**
- Modify: `home-assistant/lubelogger_mcp/launch.mjs`
- Modify: `.env.example`, `README.md`
- Test: `test/auth-config.mjs`

**Interfaces:**
- Consumes: `check_options(options)`, `buildEnv(options)` as they are today.
- Produces: no new names; `is_set` returns false for whitespace-only strings, and `buildEnv` drops them.

- [ ] **Step 1: Write the failing tests** in `test/auth-config.mjs`:
  - `whitespace-only options count as unset`: `check_options({ ...addonOptions, public_url: "   " })` names `public_url`; `buildEnv({ ...addonOptions, oidc_issuer: "  " }).OIDC_ISSUER === undefined`.
  - `oidc alone does not need home_assistant_public_url`: options with `homeassistant: false`, `oidc: true`, the OIDC settings and no `home_assistant_public_url` give no problems.

- [ ] **Step 2: Run the tests and confirm the first fails.** Run: `npm test`.

- [ ] **Step 3: Implement.** `is_set(value)` is `typeof value === "string" && value.trim() !== ""`; `buildEnv`'s final filter uses `is_set`. Values that are set are passed as they are, not trimmed.

- [ ] **Step 4: Edit the docs.**
  - `.env.example`: one comment line above each of `OIDC_ALLOWED_EMAILS`, `OIDC_ALLOWED_SUBJECTS` and `OIDC_REQUIRED_GROUP`; move `LUBELOGGER_ALLOWED_USERS` out of the OIDC block into a LubeLogger sign-in block of its own; split the 139-character line 14 into two comment lines; replace "Home Assistant mode" on `DATA_DIR` and `ALLOWED_REDIRECT_HOSTS` with "when a sign-in method is on".
  - `README.md`: tag the environment-variable fences as `env`, and update every startup-log example to the current form `listening on http://0.0.0.0:3000, endpoint /mcp, auth <methods>` (or `auth token`).
  - Mark each item this plan finished under the two follow-up sections of the design doc as done, the way "Carried into step 2" does, and leave the two out-of-scope items open.

- [ ] **Step 5: Run the tests and confirm they pass.** Run: `npm test`.

- [ ] **Step 6: Commit.** Subject: `Polish the launcher checks and sign-in docs`.

---

### Task 6: Pin the add-on

Done by the controller after the final review, not by an implementer.

- [ ] Set `home-assistant/lubelogger_mcp/config.yaml` `version` to `0.7.1-<short sha of the last code commit>` and the `Dockerfile`'s `ARG REF` to its full SHA; commit `Pin the add-on to the follow-ups build`.
- [ ] Deploy only after the owner says yes: fast-forward `main` in the main checkout, push, verify with `git ls-remote`, back up the add-on, copy the three add-on files, `ha store reload`, update with filtered output, then check the version, the startup log and a `list_vehicles` call through the connector.
