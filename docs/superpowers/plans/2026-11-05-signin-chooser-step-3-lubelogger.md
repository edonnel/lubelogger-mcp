# Sign-in Chooser, Step 3 (LubeLogger password and API key) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the last two sign-in methods: a LubeLogger username and password, and a person's own LubeLogger API key. Both are forms on the sign-in screen, with rate limiting, and an API-key connection acts with that person's own key.

**Architecture:** A new kind of login method, `FormLoginMethod`, checks typed credentials instead of redirecting. Two implementations call LubeLogger's `/api/whoami`. The provider gains a form path next to the redirect path: it checks the rate limiter, calls `check`, and either re-shows the screen with an error or completes the sign-in the same way the callback does. The sign-in screen renders the two forms. `clientFor` gives an API-key connection a LubeLogger client built with that person's key.

**Tech Stack:** TypeScript on Node ≥ 22.4, Express 5, `@modelcontextprotocol/sdk` 1.32.1, zod 4, `openid-client` 6.8.8 (unchanged). No new dependencies. Tests are plain `node:assert` scripts run by `npm test`.

**Spec:**
- `docs/superpowers/specs/2026-11-04-oauth-design.md`: the "LubeLogger API key" and "LubeLogger username and password" methods, and the anti-goals on privilege gain and stored passwords.
- `docs/superpowers/specs/2026-11-05-signin-chooser-design.md`: the screen layout, form locking, wrong-password handling and rate limiting. Where they differ, this one wins.

## Facts read from LubeLogger 1.7.4 (`Middleware/Authen.cs`, `Controllers/APIController.cs`)

- **`GET /api/whoami`** answers `{ username, emailAddress, isAdmin, isRoot }` for whoever the credentials belong to. Both HTTP Basic and `x-api-key` work. With the `culture-invariant` header the property names are camelCase.
- **When LubeLogger's login is switched off** (`EnableAuth=false`), every request, credentials or none, is treated as the root user `admin`. Bad credentials then "succeed".
- **Basic auth splits on `:`**, so a password that contains a colon can never pass. That's a LubeLogger limitation.
- **Bad credentials** get a 401.

## Calls made in this plan (not in the specs)

These are mine; the owner reviews them with the plan.

- **Refuse when LubeLogger's login is off.** Before trusting any credential, each method calls `/api/whoami` with no credentials. A 200 means LubeLogger's login is off. The method then refuses, with "LubeLogger's own login is turned off, so it can't confirm who you are. Turn it on in LubeLogger's settings." Otherwise anyone could sign in with any password or key, which is the design's privilege-gain anti-goal.
- **Identity:** `person.id` is the LubeLogger username returned by `/api/whoami`, not the typed username. `person.name` is the same.
- **Password recheck is local.** The password is never stored, so a refresh only checks that the username is still in `LUBELOGGER_ALLOWED_USERS`. The OAuth design already says a password change doesn't end the connection.
- **API key recheck** calls `/api/whoami` with the stored key:
  - a 401 is refused (the key was deleted);
  - a different username is refused;
  - LubeLogger's login being off is refused;
  - a network error or a 5xx is unavailable.
- **Cleanup does nothing** for either method. The server must never delete a person's API key in LubeLogger, and a password session leaves nothing upstream.
- **A refusal is not a failed attempt.** Correct credentials for someone not on the allowlist get the "Not allowed" page and end that login state, as a callback refusal does. They don't count toward the lockout. Wrong credentials re-show the screen and do count.
- **The shared key becomes optional** only when `lubelogger-key` is the only method on, as the OAuth design says. Token mode and every other method still require it.

## Global Constraints

- Match each file's existing style: 2-space TypeScript in `src/`, 2-space ESM in `test/*.mjs`, tabs and `snake_case` helpers in `home-assistant/lubelogger_mcp/launch.mjs`.
- No new dependencies.
- **A typed password is never stored**, in any form, and never logged. A typed or stored API key is never logged and never put on a page. Usernames in logs go through `JSON.stringify`, truncated to 60 characters.
- The sign-in screen needs no JavaScript and keeps `PAGE_HEADERS` exactly. Password and key inputs carry `autocomplete="current-password"` and `autocomplete="off"` respectively. The username input carries `autocomplete="username"`.
- The `lm_login` cookie, the Origin check and the method check run before any credential is looked at, exactly as for the redirect methods.
- Method names are exactly `homeassistant`, `oidc`, `lubelogger-password` and `lubelogger-key`. After this step all four are available.
- **Rate limiting:** five failures in 15 minutes locks the address for 15 minutes, and, for the password form, also the username. During a lockout no credential is sent to LubeLogger. The lockout message is identical whether or not the username exists.
- Test data is fictional only (alice, bob, carol; `example.com`).
- Commit messages are an imperative subject of 50 characters or fewer, with no AI attribution, and never `--no-verify`.
- `npm test` must pass at the end of every task.

## Review Focus

Each of these has a test in the task that owns it.

1. **LubeLogger with its login switched off** must refuse every password and key, at sign-in and on refresh. Never treat it as success. Owned by Task 2.
2. **An API-key connection must make every LubeLogger call with its own key,** never the shared one. A person whose key can't see a vehicle must not see it through the server. Owned by Task 4.
3. **A wrong password must not use up the login state or lock the method,** so the person can retry, or switch to another method, on the same screen. A correct one locks it. Owned by Task 4.
4. **The sixth failure in 15 minutes** must be refused without LubeLogger being called, both from one address with many usernames and for one username from many addresses. The lockout lifts after 15 minutes. Owned by Task 3 (the counter) and Task 4 (wired to the form).
5. **A typed password or key must never appear** in a log line, a page, an error or the data file. That includes a failed attempt's re-shown screen, which keeps the username but clears both secret fields. Owned by Tasks 2 and 4.

---

### Task 1: Config for the LubeLogger methods

**Files:**
- Modify: `src/config.ts`
- Test: `test/auth-config.mjs`

**Interfaces:**
- Produces:
  - `Config.LUBELOGGER_ALLOWED_USERS: string[]`: comma-split, trimmed, empty entries dropped, case kept.
  - `Config.LUBELOGGER_API_KEY?: string`: now optional in the type.
  - All four methods are available.

- [ ] **Step 1: Write the failing tests** in `test/auth-config.mjs`. `ll` is `{ ...base, PUBLIC_URL: "https://mcp.example.com" }`.

```js
await check("lubelogger-password needs an allowlist of usernames", () => {
  const no = validateConfig({ ...ll, AUTH_METHODS: "lubelogger-password" });
  assert.ok(no.problems.some((p) => p.startsWith("LUBELOGGER_ALLOWED_USERS") && /lubelogger-password sign-in method/.test(p)));
  const yes = validateConfig({ ...ll, AUTH_METHODS: "lubelogger-password", LUBELOGGER_ALLOWED_USERS: " alice , bob " });
  assert.ok(yes.ok, JSON.stringify(yes.problems));
  assert.deepEqual(yes.config.LUBELOGGER_ALLOWED_USERS, ["alice", "bob"]);
});
await check("lubelogger-key alone needs no shared key; anything else still does", () => {
  const { LUBELOGGER_API_KEY, ...noKey } = ll;
  assert.ok(validateConfig({ ...noKey, AUTH_METHODS: "lubelogger-key" }).ok);
  const both = validateConfig({ ...noKey, AUTH_METHODS: "lubelogger-key,lubelogger-password", LUBELOGGER_ALLOWED_USERS: "alice" });
  assert.ok(both.problems.some((p) => p.startsWith("LUBELOGGER_API_KEY")));
  assert.equal(validateConfig({ ...noKey, MCP_AUTH_TOKEN: "x".repeat(24) }).ok, false);
});
await check("all four methods can be on together", () => {
  const r = validateConfig({ ...ha, ...oidc, AUTH_METHODS: "homeassistant,oidc,lubelogger-password,lubelogger-key", LUBELOGGER_ALLOWED_USERS: "alice" });
  assert.ok(r.ok, JSON.stringify(r.problems));
});
```

`base`, `ha` and `oidc` are the file's existing helpers. If `base` lacks `LUBELOGGER_API_KEY`, adapt the destructure to the file's real shape.

- [ ] **Step 2: Run `npm test`.** Expected: FAIL.
- [ ] **Step 3: Implement in `src/config.ts`.**
  - Add the two methods to `AVAILABLE_METHODS`.
  - Make `LUBELOGGER_API_KEY` optional in the schema, then require it in the refinement whenever the method list is empty (token mode) or holds anything besides `lubelogger-key`. Keep today's message text: `is required (create one in LubeLogger, Editor role is enough)`.
  - Require `LUBELOGGER_ALLOWED_USERS`, with at least one entry, while `lubelogger-password` is on: `is required when the lubelogger-password sign-in method is on`.
  - Update any existing assertion about the two methods being unavailable.
  - Fix every place `tsc` flags now that the key may be undefined. In `app.ts`, the shared client is built only when the key is present. That is the seam Task 4 completes.
- [ ] **Step 4: Run `npm test`.** Expected: PASS.
- [ ] **Step 5: Commit**, as "Add config for the LubeLogger sign-in methods".

---

### Task 2: The two LubeLogger login methods

**Files:**
- Modify: `src/auth/login-method.ts`
- Create: `src/auth/lubelogger-login.ts`, `test/lubelogger-login.mjs`. Add `node test/lubelogger-login.mjs` to the `test` script after `oidc`.

**Interfaces:**
- Produces, in `login-method.ts`:

```ts
export type FormFields = { username?: string; password?: string; apiKey?: string };
export type FormCheckResult =
  | { person: Person; upstream: Record<string, unknown> }   // signed in
  | { invalid: string }                                     // wrong credentials: re-show the form, counts as a failure
  | { refused: string; person?: Person }                    // real credentials, not allowed: "Not allowed" page
  | { unavailable: string };                                // LubeLogger unreachable or 5xx: try again shortly
export interface FormLoginMethod {
  readonly form: "password" | "key";
  check(fields: FormFields): Promise<FormCheckResult>;
  recheck(upstream: Record<string, unknown>): Promise<RecheckResult>;
  cleanup(upstream: Record<string, unknown>): Promise<void>;
}
export type AnyLoginMethod = LoginMethod | FormLoginMethod;
export const isFormMethod = (m: AnyLoginMethod): m is FormLoginMethod => "check" in m;
```

- Produces, in `lubelogger-login.ts`:
  - `new LubeLoggerPasswordLogin({ lubeloggerUrl, allowedUsers, timeoutMs })`, with `form: "password"` and upstream `{ username }`;
  - `new LubeLoggerKeyLogin({ lubeloggerUrl, timeoutMs })`, with `form: "key"` and upstream `{ username, apiKey }`.

- [ ] **Step 1: Write the failing tests** in `test/lubelogger-login.mjs`, against a mock LubeLogger on `node:http`.
  - **The mock's `/api/whoami`** knows:
    - user `alice` with password `pw-alice`;
    - user `bob` with password `pw-bob`;
    - the API key `key-alice`, which belongs to alice.
  - **Its answers:**
    - 200 `{ username, emailAddress, isAdmin, isRoot }` for valid Basic or `x-api-key`;
    - 401 otherwise;
    - a switch `authOff` answers 200 `{ username: "admin", isRoot: "True" }` to everything;
    - a switch `status` forces 500.
  - **Checks to write in full:**
    - **"password: an allowlisted user with the right password signs in"**: `person { id: "alice", name: "alice" }`, upstream `{ username: "alice" }`. The mock received `Authorization: Basic` for `alice:pw-alice`.
    - **"password: a wrong password is invalid; an unknown user is invalid with the same message"**: both results deep-equal one another.
    - **"password: a correct password for someone not allowlisted is refused"**: bob with `allowedUsers: ["alice"]`.
    - **"password: a password containing a colon is invalid without a network call"**: the mock sees no request.
    - **"password: empty fields are invalid without a network call"**.
    - **"key: a valid key signs in as its owner, and the upstream keeps the key"**.
    - **"key: an unknown key is invalid"**.
    - **"LubeLogger with its login off refuses every password and key, at sign-in and on recheck"**: set `authOff`, then check the password method, the key method, and `recheck` on a stored key upstream. Each is refused, and the message mentions that LubeLogger's login is turned off.
    - **"a 500 or an unreachable LubeLogger is unavailable"**: for `check` on both methods, and for key `recheck`.
    - **"password recheck follows the allowlist only, with no network call"**: ok for alice; refused after building a method whose `allowedUsers` lacks alice; the mock sees no request.
    - **"key recheck: a deleted key is refused; another owner is refused"**: after removing the key from the mock, 401 gives refused. After pointing the key at bob, a username mismatch gives refused.
    - **"cleanup does nothing and calls nothing"**.
    - **"no password or key appears in any result message or thrown error"**: collect every result and error string from the checks above, then assert that none contains `pw-alice`, `pw-bob` or `key-alice`.
- [ ] **Step 2: Run `npm run build && node test/lubelogger-login.mjs`.** Expected: FAIL.
- [ ] **Step 3: Implement.**
  - **Shared helper:** `whoami(headers): Promise<{ status: number; username?: string }>`.
    - It uses `fetch` with `redirect: "error"`, an `AbortSignal.timeout(timeoutMs)`, and the `culture-invariant` header.
    - It reads `username` from the JSON. Network errors and timeouts surface as a thrown `Error("LubeLogger could not be reached")`.
  - **The login-off probe** is `whoami({})` with no credentials. A 200 means LubeLogger's login is off, and the method returns `refused` with the message in "Calls made in this plan".
  - **Messages:**
    - `invalid` for the password form: "That username or password is wrong." For the key form: "That API key is not valid."
    - `refused`: "<username> is not allowed to use LubeLogger MCP."
    - `unavailable`: "LubeLogger can't be reached right now. Try again shortly."
  - **Key recheck:** username mismatch or 401 is refused, the login-off probe is refused, and a 5xx or a throw is unavailable.
- [ ] **Step 4: Run `npm test`.** Expected: PASS.
- [ ] **Step 5: Commit**, as "Add the LubeLogger password and key methods".

---

### Task 3: The failed-attempt limiter

**Files:**
- Create: `src/auth/rate-limit.ts`, `test/rate-limit.mjs`. Add `node test/rate-limit.mjs` to the `test` script after `lubelogger-login`.

**Interfaces:**
- Produces:

```ts
export const MAX_FAILURES = 5;
export const WINDOW_MS = 15 * 60_000;
export class FailureLimiter {
  constructor(now?: () => number);
  /** Milliseconds until every given key is free again, or 0 when none is locked. */
  lockedFor(keys: readonly string[]): number;
  /** Records one failure against each key. */
  fail(keys: readonly string[]): void;
}
```

Keys are opaque strings. Task 4 passes `addr:<ip>` and `user:<lowercased username>`.

- [ ] **Step 1: Write the failing tests** in `test/rate-limit.mjs`, using an injected clock.
  - "five failures lock the key for 15 minutes; it is free again after".
  - "failures older than 15 minutes don't count". Use a sliding window: only failures within the last `WINDOW_MS` count.
  - "a locked username locks every address that tries it, and a locked address locks every username". `lockedFor(["addr:a","user:x"])` is non-zero when either key is locked.
  - "memory stays bounded". After 100,000 distinct keys with one failure each and the clock moved past the window, one more `fail` call prunes the expired entries: an exported `size()` used only for tests drops to 1.
- [ ] **Step 2: Run the build and the test.** Expected: FAIL.
- [ ] **Step 3: Implement.** Keep a `Map<string, number[]>` of failure timestamps per key. `lockedFor` returns the time until the oldest counted failure leaves the window, for any key with at least `MAX_FAILURES` counted. Prune expired keys at most once per minute, inside `fail`.
- [ ] **Step 4: Run `npm test`.** Expected: PASS.
- [ ] **Step 5: Commit**, as "Add a failed sign-in limiter".

---

### Task 4: Forms on the sign-in screen, and per-connection keys

**Files:**
- Modify: `src/auth/provider.ts`, `src/auth/signin-page.ts`, `src/app.ts`
- Test: `test/oauth-ha.mjs`

**Interfaces:**
- Consumes: `FormLoginMethod`, `AnyLoginMethod` and `isFormMethod` (Task 2), `FailureLimiter` (Task 3), and the config from Task 1.
- Produces:
  - **`LoginProvider`** accepts `ReadonlyMap<MethodName, AnyLoginMethod>` for both `methods` and `retired`. A new `opts.limiter?: FailureLimiter` defaults to `new FailureLimiter(now)`.
  - **`signInPage(opts)`** gains `forms?: { password?: boolean; key?: boolean }`, plus `error?: { form: "password" | "key"; message: string }` and `username?: string`. With those, it re-renders the screen after a failed attempt.
  - **`AuthInfo.extra.lubeloggerKey?: string`:** set only for `lubelogger-key` connections. `clientFor(auth)` in `app.ts` returns a `LubeLoggerClient` built with that key, and otherwise the shared client.
  - **`AppDeps.limiter?: FailureLimiter`**, so tests can inject a clock. `app.ts` passes it to the provider as `opts.limiter`.

- [ ] **Step 1: Write the failing tests** in `test/oauth-ha.mjs`, with two stub form methods.
  - `stubPassword` is `{ form: "password", check }`. It answers `alice`/`right` with a person, `bob`/`right` with refused, anything else with invalid "That username or password is wrong.", and `unavailable` when its `down` flag is set. It counts `checks`.
  - `stubKey` is `{ form: "key", check }`. It answers `key-alice` with person `alice` and upstream `{ username: "alice", apiKey: "key-alice" }`.
  - Build the app with all four methods on: the HA and OIDC stubs plus these two.
  - Give it a mock LubeLogger that records which `x-api-key` each request carried. Extend the file's existing mock.
  - **Checks to write in full:**
    - **"the screen shows buttons, then 'or', then the password form, then the key form behind 'Use a LubeLogger API key instead'"**:
      - assert the order of the markers in the HTML;
      - assert `autocomplete="current-password"` and `autocomplete="username"`;
      - assert no `value=` on the password and key inputs.
    - **"with the password method off, the key form is open and has no 'instead' summary"**.
    - **"a right password signs in and the code exchanges for tokens"**.
    - **"a wrong password re-shows the screen with the error and the username, clears the secrets, and keeps the state usable"**:
      - the response is 400 and has the error and `value="alice"`;
      - it doesn't have the typed password;
      - the same `loginState` then succeeds with the right password;
      - after that, the same state with the Home Assistant button gets "Login expired".
    - **"a wrong password, then a Home Assistant button press, on the same state works"**.
    - **"a refused person gets the Not allowed page and the state is used up"**.
    - **"LubeLogger unreachable shows 'try again shortly' and keeps the state"**.
    - **"the sixth failure in 15 minutes is refused without calling the method, for one address and many usernames, and for one username from many addresses"**:
      - use `X-Forwarded-For` to vary the address; `trust proxy 1` is already set;
      - assert `stubPassword.checks` stops growing;
      - assert the lockout message is the same for a real and an unknown username;
      - move the injected clock 15 minutes and assert a try is allowed again.
    - **"an API-key connection calls LubeLogger with its own key; others use the shared key"**:
      - sign in with `key-alice`, call `list_vehicles` over MCP, and assert the mock saw `x-api-key: key-alice`;
      - then do the same with a Home Assistant connection and assert it saw the shared key.
    - **"no typed password or key reaches a log or the data file"**: after the checks above, scan `logs` and `oauth.json` for `right`-style passwords used in this section (use distinctive values such as `PW-PLANTED-71`) and assert none appear. `key-alice` may appear in `oauth.json`, since the design stores it; it must not appear in `logs`.
- [ ] **Step 2: Run `npm test`.** Expected: FAIL.
- [ ] **Step 3: Implement.**
  - **`provider.ts`, `handleChoose`:** after the existing state, Origin, cookie and method checks, branch on `isFormMethod`.
    - **Redirect methods** are unchanged.
    - **Form methods:**
      1. Read `username`, `password` and `apiKey` from the body, as strings, each capped at 512 characters. Cap anything longer, so it never reaches LubeLogger at full length.
      2. Build the limiter keys: `addr:<req.ip>`, plus `user:<lowercased username>` for the password form.
      3. If `lockedFor` is non-zero, re-show the screen with the error "Too many attempts. Try again in <N> minutes." N rounds up. Make no check call.
      4. Call `check`:
         - `invalid` records a failure and re-shows the screen with the error above that form, keeping the username;
         - `unavailable` re-shows the screen with the message, without recording a failure;
         - `refused` logs `sign-in refused for <who>` and sends the "Not allowed" page, deleting the state and clearing the cookie;
         - success completes the sign-in exactly as `handleCallback` does after `finish`. Factor that tail into one private method shared by both: delete the state, clear the cookie, store the code, log `login by`, redirect.
      5. A failed attempt keeps the state unlocked (`entry.method` stays unset).
    - **Logs:** wrong credentials log `sign-in failed for <JSON username, max 60>` (password form) or `sign-in failed with an API key` (key form). Never log the value.
  - **`provider.ts`, `verifyAccessToken`:** add `lubeloggerKey` to `extra` when the connection's method is `lubelogger-key`, read from the grant. Copy it from the connection's upstream when the grant is issued.
  - **`signin-page.ts`:**
    - Order and markup follow the design and the step 1 mockup: the buttons, then an "or" divider only when both buttons and a form show, then the password form, then the key form inside `<details>`.
    - Each form posts to `/login` with the hidden `loginState` and `method`.
    - The error box sits above the form it belongs to. A key-form error opens the `<details>`.
    - All values are escaped.
  - **`app.ts`:**
    - build the two methods from config, as on or as retired;
    - pass `limiter`;
    - finish `clientFor`, building a key client once per request from `auth.extra.lubeloggerKey`. Never cache it by key.
- [ ] **Step 4: Run `npm test`.** Expected: PASS.
- [ ] **Step 5: Commit**, as "Add password and key forms to sign-in".

---

### Task 5: Add-on options

**Files:**
- Modify: `home-assistant/lubelogger_mcp/launch.mjs`, `home-assistant/lubelogger_mcp/config.yaml`
- Test: `test/auth-config.mjs`

- [ ] **Step 1: Write the failing tests** next to the existing launcher checks.
  - "the lubelogger_password and lubelogger_key checkboxes add their methods in order": `homeassistant,oidc,lubelogger-password,lubelogger-key`. `validateConfig(buildEnv(options)).ok` holds with `lubelogger_allowed_users: "alice"`.
  - "lubelogger_password on without lubelogger_allowed_users names it".
  - "lubelogger_key alone needs no lubelogger_api_key; anything else still does". `check_options` names `lubelogger_api_key` in the second case and never prints its value.
- [ ] **Step 2: Run `npm test`.** Expected: FAIL.
- [ ] **Step 3: Implement.**
  - **Checkboxes:** `lubelogger_password` and `lubelogger_key` are on only when exactly `true`, like `oidc`.
  - **`buildEnv`:** passes `LUBELOGGER_ALLOWED_USERS` whenever it is set.
  - **`check_options`:** requires `lubelogger_allowed_users` while `lubelogger_password` is on, and `lubelogger_api_key` unless `lubelogger_key` is the only method on.
  - **`config.yaml`:**
    - under `options`: `lubelogger_password: false` and `lubelogger_key: false`;
    - under `schema`: `lubelogger_password: bool?`, `lubelogger_key: bool?` and `lubelogger_allowed_users: str?`, and `lubelogger_api_key: password?`.
    - Leave `version` alone.
- [ ] **Step 4: Run `npm test`.** Expected: PASS.
- [ ] **Step 5: Commit**, as "Add LubeLogger sign-in options to the add-on".

---

### Task 6: Documentation

**Files:**
- Modify: `README.md`, `.env.example`, `docs/superpowers/specs/2026-11-05-signin-chooser-design.md`

- [ ] **Step 1: Update the README.** Add a "Sign in with LubeLogger" section covering:
  - both methods, and the allowlist for passwords;
  - that an API-key connection acts with that person's own LubeLogger permissions, and deleting the key ends it at the next refresh;
  - that a password change does not end a connection;
  - that LubeLogger's own login must be on;
  - that passwords containing `:` can't work (a LubeLogger API limitation);
  - the lockout rule.

  Update "Changes from upstream", the methods row in the configuration table, and every remaining "not available in this version".
- [ ] **Step 2: Update `.env.example`.** Add `LUBELOGGER_ALLOWED_USERS`, and say `LUBELOGGER_API_KEY` is optional when `lubelogger-key` is the only method. One comment line goes above each variable.
- [ ] **Step 3: Update the chooser design.** Add a "Step 3 done" line naming the plan.
- [ ] **Step 4: Check the docs.** Run `npm test`. Expected: PASS. Also run `grep -n "not available in this version" README.md .env.example`. Expected: no line.
- [ ] **Step 5: Commit**, as "Document LubeLogger sign-in".

---

### Task 7: Pin the add-on (controller, after the final review)

- [ ] **Step 1: Pin the build.** In `Dockerfile`, set `ARG REF=` to the last reviewed commit. In `config.yaml`, set `version: "0.7.0-<first 7>"`.
- [ ] **Step 2: Run `npm test`, then commit**, as "Pin the add-on to the LubeLogger sign-in build".
- [ ] **Step 3: Ask the owner before merging, pushing or deploying.**
- [ ] **Step 4: On their yes, push before deploying.** Fast-forward `main` in its own checkout (where `main` is checked out) and push it before updating the add-on, because the add-on builds from GitHub at the pinned SHA. That lesson comes from the 0.6.0 deploy. Then back up the add-on and update it. The deploy check:
  - the add-on updates with no settings changed;
  - the screen shows only the Home Assistant button;
  - the existing connection keeps working.
