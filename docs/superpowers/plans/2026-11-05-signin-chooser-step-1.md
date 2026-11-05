# Sign-in Chooser, Step 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let OAuth run a list of sign-in methods (`AUTH_METHODS`) shown on one sign-in screen that replaces the approval page, with Home Assistant as the only method that works so far.

**Architecture:** Config resolves `AUTH_METHODS` (or the old `AUTH_MODE`) into a list of method names. `LoginProvider` holds a map of name to `LoginMethod` instead of one method. The approval page becomes a sign-in screen whose buttons post the method's name, and connections, access grants and confirmation owners carry the method. The add-on's launcher builds `AUTH_METHODS` from a checkbox and checks its own options, so an upgrade never fails inside the Supervisor.

**Tech Stack:** TypeScript on Node ≥ 22.4, Express 5, `@modelcontextprotocol/sdk` 1.32.1, zod 4, plain `node:assert` test scripts run by `npm test`.

**Spec:** `docs/superpowers/specs/2026-11-05-signin-chooser-design.md`, which amends `docs/superpowers/specs/2026-11-04-oauth-design.md`. Read both. This plan covers the design's delivery step 1 only. Steps 2 (OpenID Connect) and 3 (the LubeLogger methods) get their own plans.

**Precondition:** branch from `main` after `docs/readme-upgrade-note` and `docs/signin-chooser-design` are merged into it, so the README already has the 0.3 → 0.4 upgrade section that Task 5 extends.

## Global Constraints

- Match each file's existing style: 2-space TypeScript in `src/`, 2-space ESM in `test/*.mjs`, tabs and `snake_case` helpers in `home-assistant/lubelogger_mcp/launch.mjs`.
- No new dependencies.
- Never write a token, code, login state, key or password to a log or a page. Names in logs go through `who()` or `JSON.stringify`.
- The sign-in screen needs no JavaScript and keeps today's headers exactly: `Cache-Control: no-store`, `X-Frame-Options: DENY`, `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'`.
- The `lm_login` cookie, the Origin check and the single-use login state from release 1 apply to every method.
- Method names are exactly `homeassistant`, `oidc`, `lubelogger-password` and `lubelogger-key`. Only `homeassistant` is available in this step. The others are refused with "is not available in this version", the same wording `AUTH_MODE` uses today.
- Test data uses fictional people and hosts only (alice, bob, carol; `example.com`). The commit hooks reject real names.
- Commit messages follow the repo's style: imperative subject of 50 characters or fewer, no AI attribution, never `--no-verify`.
- `npm test` must pass at the end of every task.

## Review Focus

These failure modes are implied by the design but not covered by any test it lists. Each has a test in the task that owns it.

1. **An `oauth.json` from release 1** (connections with no `method`) must load, and those connections must refresh without logging in again. Owned by Task 2 (store) and Task 4 (refresh).
2. **Add-on options saved by 0.4** (no `homeassistant` key, both URLs set) must start the server in Home Assistant mode, not stop it. Owned by Task 3.
3. **Pressing the sign-in button twice** (Back, then press again) must not break the login already under way: the second press gets the start-again page and the first login still finishes. Owned by Task 4.
4. **A form with no `method` field**, e.g. a 0.4 approval page still open in a tab, gets the "not available" page. The state is kept. Owned by Task 4.
5. **Markup in the app's name** and an attacker-chosen `method` value are escaped on the page and JSON-quoted in the log, never echoed raw. Owned by Task 4.

---

### Task 1: `AUTH_METHODS` in config

**Files:**
- Modify: `src/config.ts`
- Test: `test/auth-config.mjs`

**Interfaces:**
- Produces:
  - `export const METHOD_NAMES = ["homeassistant", "oidc", "lubelogger-password", "lubelogger-key"] as const;`
  - `export type MethodName = (typeof METHOD_NAMES)[number];`
  - `Config.AUTH_METHODS: MethodName[]`. It is always present after validation: empty in token mode, otherwise the resolved list in the order given.
  - `Config.AUTH_MODE` keeps its current values and default.

- [ ] **Step 1: Write the failing tests** in `test/auth-config.mjs`. Use the file's existing `check` helper and a base env holding `LUBELOGGER_URL`, `LUBELOGGER_API_KEY`, `PUBLIC_URL`, `HOME_ASSISTANT_PUBLIC_URL` and `HOME_ASSISTANT_URL`.

```js
await check("AUTH_METHODS=homeassistant resolves to that list", () => {
  const r = validateConfig({ ...ha, AUTH_METHODS: "homeassistant" });
  assert.ok(r.ok, JSON.stringify(r.problems));
  assert.deepEqual(r.config.AUTH_METHODS, ["homeassistant"]);
});
await check("AUTH_METHODS trims spaces around names", () => {
  const r = validateConfig({ ...ha, AUTH_METHODS: " homeassistant " });
  assert.deepEqual(r.config.AUTH_METHODS, ["homeassistant"]);
});
await check("AUTH_MODE=homeassistant still works and means the same list", () => {
  const r = validateConfig({ ...ha, AUTH_MODE: "homeassistant" });
  assert.deepEqual(r.config.AUTH_METHODS, ["homeassistant"]);
});
await check("token mode has no methods", () => {
  const r = validateConfig({ ...base, MCP_AUTH_TOKEN: "x".repeat(24) });
  assert.deepEqual(r.config.AUTH_METHODS, []);
});
await check("AUTH_METHODS refuses unknown, duplicate and empty lists", () => {
  for (const [value, needle] of [
    ["homeassistant,nope", /nope/],
    ["homeassistant,homeassistant", /more than once/],
    [",", /at least one/],
  ]) {
    const r = validateConfig({ ...ha, AUTH_METHODS: value });
    assert.equal(r.ok, false);
    assert.ok(r.problems.some((p) => p.startsWith("AUTH_METHODS") && needle.test(p)), r.problems.join("\n"));
  }
});
await check("methods planned for later refuse to start", () => {
  const r = validateConfig({ ...ha, AUTH_METHODS: "homeassistant,oidc" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => /oidc.*not available in this version/.test(p)));
});
await check("AUTH_METHODS with a non-token AUTH_MODE refuses to start", () => {
  const r = validateConfig({ ...ha, AUTH_MODE: "homeassistant", AUTH_METHODS: "homeassistant" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => p.startsWith("AUTH_METHODS") && /AUTH_MODE/.test(p)));
});
await check("each method's settings are required only when it is on, and token conflicts still apply", () => {
  const r = validateConfig({ ...base, AUTH_METHODS: "homeassistant", PUBLIC_URL: "https://mcp.example.com" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => p.startsWith("HOME_ASSISTANT_PUBLIC_URL") && /homeassistant/.test(p)));
  const t = validateConfig({ ...ha, AUTH_METHODS: "homeassistant", MCP_AUTH_TOKEN: "x".repeat(24) });
  assert.ok(t.problems.some((p) => p.startsWith("MCP_AUTH_TOKEN")));
});
```

`base` holds only the LubeLogger settings. `ha` is `base` plus the three URLs.

- [ ] **Step 2: Run `npm test`.** Expected: the new checks FAIL, since `AUTH_METHODS` is undefined.

- [ ] **Step 3: Implement in `src/config.ts`.**
  - Add `AUTH_METHODS` to `authSchema` as an optional string.
  - In `checkedSchema` (keep the `superRefine`, then add a `.transform`), resolve the list:
    - A non-`token` `AUTH_MODE` alone gives `[AUTH_MODE]`.
    - `AUTH_METHODS` alone gives its split, trimmed list.
    - Neither gives `[]`.
  - Validate the resolved list:
    - Unknown names: message `"<name>" is not a sign-in method (use one of …)`.
    - Duplicates: `lists "<name>" more than once`.
    - An empty list: `must list at least one sign-in method`.
    - Names outside `["homeassistant"]`: `"<name>" is not available in this version`.
    - Both settings given: `must not be set together with AUTH_MODE=<mode> (use one or the other)`, reported on `AUTH_METHODS`.
  - Replace today's `AUTH_MODE === "token"` / homeassistant branches with "the list is empty" / "the list is not empty". The `MCP_AUTH_TOKEN` and `MCP_PATH` conflicts apply whenever the list is not empty.
  - The three URL requirements apply when the list includes `homeassistant`, with the message `is required when the homeassistant sign-in method is on`. `PUBLIC_URL` gets `is required when a sign-in method is on`.
  - Update the existing assertions in `test/auth-config.mjs` that match the old "when AUTH_MODE is homeassistant" wording.

- [ ] **Step 4: Run `npm test`.** Expected: PASS, including every existing check.

- [ ] **Step 5: Commit** `src/config.ts` and `test/auth-config.mjs`, as "Add AUTH_METHODS to choose sign-in methods".

---

### Task 2: Connections record their method

**Files:**
- Modify: `src/auth/store.ts`
- Test: `test/auth-store.mjs`

**Interfaces:**
- Consumes: `MethodName` from `src/config.ts`.
- Produces:
  - `Connection.method: MethodName`, required.
  - `putConnection` replaces the existing connection with the same `clientId`, `method` and `person.id`, and returns it.
  - A stored connection without `method` loads as `"homeassistant"`.

- [ ] **Step 1: Write the failing tests** in `test/auth-store.mjs`. Add `method: "homeassistant"` to the `conn()` helper's defaults.

```js
await check("a connection with another method is kept, not replaced", async () => {
  const dir = await tmp();
  const s = await AuthStore.open(dir, () => 1000);
  await s.putConnection(conn());
  const old = await s.putConnection(conn({ id: "c2", method: "oidc", refreshHash: hashToken("r2") }));
  assert.equal(old, undefined);
  assert.ok(s.findByRefresh("client-a", "refresh-one"));
  assert.ok(s.findByRefresh("client-a", "r2"));
});

await check("a release 1 file without methods loads as homeassistant", async () => {
  const dir = await tmp();
  const legacy = conn({ refreshHash: hashToken("legacy") });
  delete legacy.method;
  await fs.writeFile(path.join(dir, "oauth.json"), JSON.stringify({ clients: {}, connections: { c1: legacy } }));
  const s = await AuthStore.open(dir, () => 1000);
  assert.equal(s.findByRefresh("client-a", "legacy")?.connection.method, "homeassistant");
});
```

Before writing it, check that the on-disk shape in the second test matches what `AuthStore` writes today. Read one file the existing tests produce, and adjust `clients`/`connections` to match.

- [ ] **Step 2: Run `npm test`.** Expected: both new checks FAIL.

- [ ] **Step 3: Implement in `src/auth/store.ts`.**
  - Add `method` to `Connection`.
  - When loading, a connection whose `method` is absent gets `"homeassistant"`. A present `method` that isn't a string is refused like any other wrong shape, without quoting the file.
  - The replacement match in `putConnection` adds `method`.

- [ ] **Step 4: Run `npm test`.** Expected: `auth-store` passes. `oauth-ha` may fail to compile until Task 4 sets `method` on new connections. If `tsc` fails because `provider.ts` builds a `Connection` without `method`, add `method: "homeassistant"` there as a stopgap. Task 4 replaces it.

- [ ] **Step 5: Commit**, as "Record the sign-in method on each connection".

---

### Task 3: Add-on checkbox and launcher checks

**Files:**
- Modify: `home-assistant/lubelogger_mcp/launch.mjs`, `home-assistant/lubelogger_mcp/config.yaml`
- Test: `test/auth-config.mjs` (it already imports `buildEnv`)

**Interfaces:**
- Consumes: the `AUTH_METHODS` setting from Task 1.
- Produces:
  - `export function buildEnv(options)`: sets `AUTH_METHODS` and never sets `AUTH_MODE`.
  - `export function check_options(options): string[]`: problems as messages that name options and never contain their values.

- [ ] **Step 1: Write the failing tests** in `test/auth-config.mjs`, next to the existing `buildEnv` checks.

```js
const { buildEnv, check_options } = await import("../home-assistant/lubelogger_mcp/launch.mjs");

await check("0.4 options without a homeassistant key start in Home Assistant mode", () => {
  const env = buildEnv(addonOptions);
  assert.equal(env.AUTH_METHODS, "homeassistant");
  assert.equal(env.AUTH_MODE, undefined);
  assert.deepEqual(check_options(addonOptions), []);
  assert.ok(validateConfig(env).ok);
});

await check("homeassistant: false with nothing else on is refused by the launcher", () => {
  const problems = check_options({ ...addonOptions, homeassistant: false });
  assert.equal(problems.length, 1);
  assert.match(problems[0], /at least one sign-in method/);
});

await check("a missing URL is named, and no option value appears in any message", () => {
  const options = { ...addonOptions, lubelogger_api_key: "SECRET-PLANTED-77", public_url: "" };
  const problems = check_options(options);
  assert.ok(problems.some((p) => /public_url/.test(p)));
  assert.ok(problems.every((p) => !p.includes("SECRET-PLANTED-77")));
  assert.ok(check_options({ ...addonOptions, home_assistant_public_url: undefined }).some((p) => /home_assistant_public_url/.test(p)));
});
```

`addonOptions` is the file's existing 0.4-style object, which has no `homeassistant` key.

- [ ] **Step 2: Run `npm test`.** Expected: FAIL, since `check_options` is not exported.

- [ ] **Step 3: Implement.**
  - **`launch.mjs`:**
    - The `homeassistant` checkbox is on unless the option is exactly `false`.
    - `buildEnv` sets `AUTH_METHODS` to the comma-joined list of methods that are on, and drops `AUTH_MODE`.
    - `check_options` returns these problems:
      - `switch on at least one sign-in method` when none is on.
      - `<option> is required while the homeassistant sign-in method is on`, for each of `public_url` and `home_assistant_public_url` that is empty or missing.
    - In the entry-script block, run `check_options` before anything else. If it finds problems, print each as `lubelogger-mcp add-on: <problem>` and exit 1.
  - **`config.yaml`:**
    - Add `homeassistant: true` under `options`, and `homeassistant: bool?` under `schema`.
    - Make `public_url: url?` and `home_assistant_public_url: url?`.
    - Leave `version` alone. Task 6 sets it.

- [ ] **Step 4: Run `npm test`.** Expected: PASS.

- [ ] **Step 5: Commit**, as "Check add-on options in the launcher".

---

### Task 4: The sign-in screen and several methods in the provider

**Files:**
- Create: `src/auth/signin-page.ts`
- Modify: `src/auth/provider.ts`, `src/auth/routes.ts`, `src/app.ts`, `src/tools.ts`
- Test: `test/oauth-ha.mjs`

**Interfaces:**
- Consumes: `MethodName` and `Config.AUTH_METHODS` (Task 1), and `Connection.method` (Task 2).
- Produces:
  - **`signin-page.ts`:**
    - `export const PAGE_HEADERS: Record<string, string>`: the three headers in Global Constraints. `provider.ts`'s `sendPage` uses it too.
    - `export type MethodChoice = { method: MethodName; label: string };`
    - `export function signInPage(opts: { appName: string; returnHost: string; loginState: string; choices: MethodChoice[] }): string`: a whole HTML document.
    - `export const BUTTON_LABEL: Record<MethodName, string>`: `homeassistant` is `"Continue with Home Assistant"`. Step 2 overrides the `oidc` label with the provider's display name, so here it is `"Continue with single sign-on"`. The two LubeLogger entries are `"Sign in with LubeLogger"` and `"Sign in with an API key"`; they get their forms in step 3.
  - **`LoginProvider`:**
    - Constructor `(store: AuthStore, methods: ReadonlyMap<MethodName, LoginMethod>, now?, opts?)`. It throws if `methods` is empty.
    - `handleChoose(req, res)` replaces `handleApprove`.
  - **`AuthInfo.extra`** is `{ method, personId, personName }`.
  - **`ownerOf(extra)`** returns `"<method>:<personId>"` when both are strings, and `"token"` otherwise.
  - **`AppDeps.loginMethods?: Partial<Record<MethodName, LoginMethod>>`** replaces `loginMethod`. Each method in `config.AUTH_METHODS` takes its injected stub if given, else its real implementation.
  - In `app.ts`, `createServer(client: LubeLoggerClient)` is called per request with `clientFor(req.auth)`. In this step `clientFor(auth?: AuthInfo): LubeLoggerClient` always returns the shared client. It is the seam step 3 fills in.

- [ ] **Step 1: Update the test helpers in `test/oauth-ha.mjs`, then write the new failing tests.**
  - `approve(loginState, cookie, headers, method = "homeassistant")` posts `{ loginState, method }`.
  - `createApp(config(), { loginMethods: { homeassistant: stub }, now })` replaces `{ loginMethod: stub }` everywhere.
  - In the existing approval-page check (around line 369), the form now carries `<button type="submit" name="method" value="homeassistant">` and the label `Continue with Home Assistant`.
  - The check at line 383 keeps its meaning: a callback for a state with no method chosen gets 400.

```js
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
  const back = await get(first.headers.get("location"), { headers: { cookie } });
  assert.equal(back.status, 302);
  // and the code from that callback still exchanges for tokens
  await exchange(claude, new URL(back.headers.get("location")).searchParams.get("code"), verifier);
});

await check("a release 1 connection refreshes without a new login", async () => {
  // write oauth.json as release 1 did (no method), then refresh through a fresh app over it
});

await check("a connection whose method is switched off is ended at refresh, and its cleanup is skipped with a log line", async () => {
  // build a LoginProvider directly over a store holding a homeassistant connection,
  // with methods = new Map([["oidc", otherStub]]); exchangeRefreshToken rejects with InvalidGrantError,
  // the connection is gone from the store, stub.cleaned did not grow, and a log line says its
  // upstream session could not be revoked
});

await check("confirmations are owned by method and person", async () => {
  // via the app: alice proposes, and the owner seen by pending is "homeassistant:id-alice"
  // (the existing alice/carol test keeps passing)
});
```

The three bodies left as comments must be written in full, using the file's existing helpers (`authorizeAs`, `exchange`, `refresh`, `start`/`stop` of the running app over `dataDir`) and the store and provider imports from `dist/`. Each comment lists the assertions to make. Use the names the file already defines if they differ from those above.

- [ ] **Step 2: Run `npm test`.** Expected: the new checks FAIL. The existing ones may also fail until the helpers match the new code.

- [ ] **Step 3: Implement.**
  - **`signin-page.ts`:**
    - The layout of the design's sign-in screen with buttons only: the title, the box naming the app and return host with "Only continue if you started this from Claude.", then one `<form method="post" action="/login">`. The form holds the hidden `loginState` and one `<button type="submit" name="method" value="…">` per choice.
    - Inline CSS styles both light and dark through `@media (prefers-color-scheme: dark)`.
    - Escape every interpolated value.
  - **`provider.ts`:**
    - `LoginState` drops `approved` and gains `method?: MethodName`, which is set when the person chooses.
    - `handleChoose`:
      1. A missing, expired or already-chosen state gets the expired page. Unlike today, a state that was already chosen is kept, so the login under way still finishes.
      2. A foreign Origin or a missing or wrong cookie gets the expired page, and the state is kept.
      3. If `body.method` is not a key of `methods`, log `sign-in with unavailable method ${JSON.stringify(String(value).slice(0, 40))} refused` and send a 400 page titled "Not available", saying "That sign-in method is not available on this server." The state is kept.
      4. Otherwise set `entry.method`, then call that method's `start`.
    - `handleCallback` requires `entry.method` and calls that method's `finish`.
    - `PendingCode`, `AccessGrant` and new connections carry `method`.
    - In `refresh`: if `methods` lacks `connection.method`, call `end(connection, "sign-in method switched off")` and throw `InvalidGrantError("Access was withdrawn")`. Otherwise re-check through that method.
    - `safeCleanup(upstream, person, method)`: when the method is not in `methods`, log `upstream session for ${who(person)} could not be revoked (sign-in method switched off)` and return.
    - `purgeOnce` also ends connections whose method is not in `methods`.
    - `authorize` sends `signInPage(...)` with `PAGE_HEADERS`. Choices are `BUTTON_LABEL` for each key of `methods`, in the order the map was built (`config.AUTH_METHODS` order).
  - **`routes.ts`:** `POST /login` calls `handleChoose`.
  - **`app.ts`:**
    - Branch on `config.AUTH_METHODS.length`.
    - Build the methods map from `config.AUTH_METHODS`, with `homeassistant` constructed as today.
    - Add the `clientFor` seam described in Interfaces.
    - The error-page condition becomes "any method is on".
  - **`tools.ts`:** `ownerOf` as described in Interfaces.

- [ ] **Step 4: Run `npm test`.** Expected: PASS, with every existing check. The secrets-in-logs check at the end of `oauth-ha.mjs` must still pass.

- [ ] **Step 5: Commit**, as "Show sign-in methods on one screen".

---

### Task 5: Documentation

**Files:**
- Modify: `README.md`, `.env.example`

**Interfaces:**
- Consumes: the setting names and page wording from Tasks 1, 3 and 4.

- [ ] **Step 1: Update `README.md`.**
  - In "Changes from upstream" and "Sign in with Home Assistant", name `AUTH_METHODS` and say `AUTH_MODE=homeassistant` still works.
  - Connect step 2 becomes: the sign-in screen names the app and where it returns to, then press **Continue with Home Assistant**.
  - Add a short paragraph: switching a method off ends its connections at their next refresh, so switch it off before deleting its settings.
  - In "Upgrading the add-on", add a 0.4 → 0.5 note: the update needs no new settings, and the new **homeassistant** checkbox is on by default.
  - Update the configuration table rows for `AUTH_MODE` and add `AUTH_METHODS`.
- [ ] **Step 2: Update `.env.example`.** Replace the `AUTH_MODE` block with `AUTH_METHODS` (commented out), keeping `AUTH_MODE=token`. Say that `homeassistant` is the one method available now, and that the two settings are never used together.
- [ ] **Step 3: Check the docs.** Run `grep -n "Approve" README.md .env.example`. Expected: no line still tells the reader to press Approve.
- [ ] **Step 4: Run `npm test`.** Expected: PASS.
- [ ] **Step 5: Commit**, as "Document sign-in methods and the new screen".

---

### Task 6: Pin the add-on (controller, after the final review)

Done by the controller only after the whole-branch review is clean, because it pins the final commit.

**Files:**
- Modify: `home-assistant/lubelogger_mcp/config.yaml`, `home-assistant/lubelogger_mcp/Dockerfile`

- [ ] **Step 1: Pin the build.** In the `Dockerfile`, set `ARG REF=` to the full SHA of the branch's last reviewed commit. In `config.yaml`, set `version` to `"0.5.0-<first 7 of that SHA>"`.
- [ ] **Step 2: Run `npm test`.** Expected: PASS.
- [ ] **Step 3: Commit**, as "Pin the add-on to the sign-in chooser build".
- [ ] **Step 4: Ask the owner before merging, pushing or deploying.** The deploy check:
  - the add-on updates and starts with no settings changed;
  - the sign-in screen shows one Home Assistant button;
  - Claude reconnects;
  - the existing connection keeps working without a new login.
