# OAuth Release 1: Core and Home Assistant Login Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let Claude's custom connectors connect through OAuth with a Home Assistant login, while token mode stays the default.

**Architecture:** The server becomes an OAuth 2.1 authorization server on the MCP SDK's server-auth framework. One provider class handles clients, codes and tokens, and delegates "who is this" to a pluggable login method. Release 1 ships the Home Assistant method. Connections persist in a JSON file in the data folder; access tokens live in memory only.

**Tech Stack:** TypeScript (strict), Express 5, `@modelcontextprotocol/sdk` 1.32.1 (`mcpAuthRouter`, `OAuthServerProvider`, `requireBearerAuth`, `getOAuthProtectedResourceMetadataUrl`, the `errors.js` classes), zod 4, Node 22 global `WebSocket`/`fetch`. The `ws` package is added as a devDependency for the mock Home Assistant only.

**Spec:** `docs/superpowers/specs/2026-11-04-oauth-design.md`

## Global Constraints

- `AUTH_MODE` is `token` (default), `homeassistant`, `oidc`, `lubelogger-key` or `lubelogger-password`. Release 1 implements `token` and `homeassistant`; the other three values are accepted by the schema but refuse to start with "not available in this version".
- In any OAuth mode, the endpoint is fixed at `/mcp`, and **startup fails if `MCP_AUTH_TOKEN` or a custom `MCP_PATH` is also set**.
- Token mode behaves exactly as today. All existing smoke checks keep passing unchanged.
- Access tokens last **1 hour** and are kept in memory only. Refresh tokens are random, stored **hashed** (SHA-256), rotated on each use, and expire after **90 days unused**.
- A connection is keyed by OAuth client ID plus person. A new login for the same pair replaces the old connection and cleans up its upstream session. No upstream session outlives its connection.
- A login method that can't be reached during a refresh yields HTTP 503 `temporarily_unavailable` without consuming the refresh token. A token is never issued without a successful re-check.
- A preview's confirmation token can only be committed by the person who proposed it.
- No token, code, key or password is ever written to a log. Logins, refusals and disconnections are logged with the person's name.
- Browser paths are `/authorize`, `/login` and `/login/callback`. Home Assistant's client ID is `PUBLIC_URL + "/"` and its redirect URI is `PUBLIC_URL + "/login/callback"`.
- Home Assistant mode requires the person's `is_admin` to be `true`, from HA's `auth/current_user`.
- Indentation and style follow the repo: 2 spaces, double quotes, semicolons, ESM.

## Review Focus

1. **Claude refreshes twice at once with the same refresh token** (retries, two devices racing). A reasonable person expects to stay connected, not be logged out. The previous refresh token stays valid for 60 seconds after rotation and returns the same new token pair (Task 3).
2. **The Home Assistant login takes longer than 10 minutes, or the browser comes back to `/login/callback` with an unknown or reused `state`.** Expected: a plain "This login link has expired, start again from Claude" page with HTTP 400, never a crash or a stack trace (Task 4).
3. **The data file is unreadable, corrupt or unwritable at startup.** Expected: the server refuses to start with a message naming the file, not silently starting with no connections (Task 2).
4. **`PUBLIC_URL` or `HOME_ASSISTANT_PUBLIC_URL` is given with a trailing slash or a path.** Expected: trailing slashes are trimmed, and a path is refused at startup, since the issuer and HA client ID must be bare origins (Task 1).
5. **A non-admin logs in, then an admin logs in from the same Claude client.** Expected: the refusal leaves nothing behind (its HA session is revoked), and the admin's login works normally (Task 4).

---

### Task 1: Mode selection and configuration

**Files:**
- Modify: `src/config.ts`
- Test: `test/auth-config.mjs` (create; plain Node script using `node:assert/strict`, in the style of `test/smoke.mjs`)
- Modify: `package.json` (`test` script runs `smoke.mjs`, then `auth-config.mjs`, `auth-store.mjs`, `oauth-ha.mjs` in that order)

**Interfaces:**
- Produces: `loadConfig(env)` returns `Config`, adding `AUTH_MODE: "token" | "homeassistant" | "oidc" | "lubelogger-key" | "lubelogger-password"`, `PUBLIC_URL?: string`, `HOME_ASSISTANT_PUBLIC_URL?: string`, `HOME_ASSISTANT_URL?: string` and `DATA_DIR: string` (default `"./data"`). Also exports `validateConfig(env): { ok: true; config: Config } | { ok: false; problems: string[] }` so tests can check rules without `process.exit`; `loadConfig` calls it.

- [ ] **Step 1: Write the failing tests in `test/auth-config.mjs`** (import `validateConfig` from `../dist/config.js`)
  - `token mode with a bearer token is valid` → `ok === true`, `config.AUTH_MODE === "token"`.
  - `homeassistant mode needs PUBLIC_URL, HOME_ASSISTANT_PUBLIC_URL and HOME_ASSISTANT_URL` → `ok === false` with three problems naming each variable.
  - `homeassistant mode refuses MCP_AUTH_TOKEN` → `ok === false`, a problem matching `/MCP_AUTH_TOKEN/`.
  - `homeassistant mode refuses a custom MCP_PATH` → `ok === false`, a problem matching `/MCP_PATH/`.
  - `homeassistant mode does not need a secret path` → valid with no `MCP_AUTH_TOKEN` and no `MCP_PATH`.
  - `trailing slashes are trimmed` → `PUBLIC_URL: "https://mcp.example.com/"` gives `"https://mcp.example.com"`.
  - `a path in PUBLIC_URL is refused` → `"https://mcp.example.com/mcp"` gives a problem matching `/PUBLIC_URL/`.
  - `oidc is not available in this version` → `ok === false`, problem matching `/not available in this version/`.
- [ ] **Step 2: Run `npm run build && node test/auth-config.mjs`.** Expected: FAIL, `validateConfig` is not exported.
- [ ] **Step 3: Implement in `src/config.ts`.** Keep the existing `schema` object untouched and layer refinements on top, as `checkedSchema` already does. Keep today's secret-path rule for token mode only.
- [ ] **Step 4: Run `npm test`.** Expected: all smoke checks and the new config checks pass.
- [ ] **Step 5: Commit** `src/config.ts`, `test/auth-config.mjs` and `package.json` (message: "Add auth mode selection to the config").

### Task 2: Connection store

**Files:**
- Create: `src/auth/store.ts`
- Test: `test/auth-store.mjs`

**Interfaces:**
- Produces:
  - `type Person = { id: string; name: string }`
  - `type Connection = { id: string; clientId: string; person: Person; upstream: Record<string, unknown>; refreshHash: string; previousRefreshHash?: string; rotatedAt?: number; lastUsedAt: number }`
  - `class AuthStore` with:
    - `static open(dir: string, now?: () => number): Promise<AuthStore>`: creates `dir` if missing, reads `oauth.json` if present, and throws an `Error` naming the file if it is unreadable or not valid JSON.
    - `getClient(id: string): OAuthClientInformationFull | undefined`
    - `saveClient(client: OAuthClientInformationFull): Promise<void>`
    - `putConnection(c: Connection): Promise<Connection | undefined>`: replaces any connection with the same `clientId` and `person.id`, and returns the replaced one so the caller can clean it up.
    - `findByRefresh(clientId: string, refreshToken: string): { connection: Connection; stale: boolean } | undefined`, where `stale` means the token matched `previousRefreshHash` inside its grace window.
    - `updateConnection(c: Connection): Promise<void>`
    - `removeConnection(id: string): Promise<Connection | undefined>`
    - `expired(c: Connection): boolean`: true when `now() - lastUsedAt > 90 days`.
    - `hashToken(t: string): string`, exported and SHA-256 hex.
  - Writes are atomic: write `oauth.json.tmp`, then rename. One `oauth.json` holds `{ clients, connections }`.

- [ ] **Step 1: Write failing tests** with an injected clock and a temp dir:
  - `a saved client survives reopening`
  - `putConnection replaces the same client and person and returns the old one`
  - `refresh tokens are stored hashed`: the raw token string does not appear in `oauth.json`.
  - `findByRefresh matches the previous token only within 60 seconds of rotation`
  - `expired is true after 90 days unused and false at 89`
  - `a corrupt oauth.json refuses to open with the file name in the error`
- [ ] **Step 2: Run `npm run build && node test/auth-store.mjs`.** Expected: FAIL, the module is not found.
- [ ] **Step 3: Implement `src/auth/store.ts`** with the interfaces above. Use `node:crypto` `randomUUID` for ids.
- [ ] **Step 4: Run `npm test`.** Expected: all pass.
- [ ] **Step 5: Commit** (message: "Add the OAuth connection store").

### Task 3: OAuth provider and wiring, with a test login method

**Files:**
- Create: `src/auth/login-method.ts`, `src/auth/provider.ts`, `src/auth/routes.ts`, `src/app.ts`
- Modify: `src/index.ts`, `src/pending.ts`, `src/tools.ts`, `src/records.ts`, `src/reminders.ts`
- Test: `test/oauth-ha.mjs` (create; in this task it builds the app in-process with a stub login method and drives the real HTTP endpoints)

There is **no test-only login switch in production code**: tests inject a stub `LoginMethod` and a clock through `createApp`, so no environment variable can turn on a fake login in a deployed server.

**Interfaces:**
- Produces in `src/auth/login-method.ts`:
  - `type RecheckResult = { ok: true; upstream: Record<string, unknown>; person: Person } | { ok: false; reason: "refused" | "unavailable" }`
  - `interface LoginMethod { start(loginState: string, res: express.Response): Promise<void>; finish(req: express.Request): Promise<{ person: Person; upstream: Record<string, unknown> } | { refused: string }>; recheck(upstream: Record<string, unknown>): Promise<RecheckResult>; cleanup(upstream: Record<string, unknown>): Promise<void> }`. `finish` reads the browser's return to `/login/callback`; `start` sends the browser to the login.
- Produces in `src/auth/provider.ts`: `class LoginProvider implements OAuthServerProvider`, built with `new LoginProvider(store: AuthStore, method: LoginMethod, now?: () => number)`. It also has `handleCallback(req, res): Promise<void>`, mounted at `GET /login/callback`.
  - `authorize` keeps `{ clientId, params }` under a random `loginState` for 10 minutes, then calls `method.start`.
  - `handleCallback` matches `loginState`. When `finish` returns `{ refused }`, it shows a 403 page with that message. When it returns a person, it issues a one-time MCP authorization code (10 minutes) and redirects to `params.redirectUri` with `code` and `state`.
  - `exchangeAuthorizationCode` creates the connection through `putConnection` and calls `method.cleanup` on any connection that was replaced. It returns `{ access_token, token_type: "bearer", expires_in: 3600, refresh_token }`.
  - `exchangeRefreshToken`, in order:
    1. If the connection is expired, clean it up and throw `InvalidGrantError`.
    2. If the refresh token is a stale match inside the grace window, return the same new pair as the first refresh (Review Focus 1).
    3. Call `method.recheck`. `refused`: clean up and throw `InvalidGrantError`. `unavailable`: throw `TemporarilyUnavailableError` and leave the store unchanged. `ok`: rotate the refresh token, update `upstream` and `lastUsedAt`, and issue a new access token.
  - `verifyAccessToken` returns `AuthInfo` with `extra: { personId, personName }` and `expiresAt` in seconds, or throws `InvalidTokenError`.
  - `revokeToken` removes the connection for a refresh token and calls `method.cleanup`.
  - `clientsStore` is backed by `AuthStore` and supports `registerClient`.
- Produces in `src/auth/routes.ts`: `mountOAuth(app: express.Express, opts: { publicUrl: string; provider: LoginProvider }): express.RequestHandler`. It mounts `mcpAuthRouter` with `issuerUrl` and `resourceServerUrl: publicUrl + "/mcp"` and the `/login/callback` route, and returns `requireBearerAuth({ verifier: provider, resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(new URL(publicUrl + "/mcp")) })` for `/mcp`. It also sets `app.set("trust proxy", 1)`, so the SDK's rate limiter accepts the tunnel's `X-Forwarded-For`.
- Modifies `PendingStore`:
  - `add(rec)` gains a required `owner: string`.
  - `take(token, owner)` returns `undefined` when `owner` doesn't match, leaving the record in place.
  - Tools pass `extra.authInfo?.extra?.personId ?? "token"`.
- Produces in `src/app.ts`: `createApp(config: Config, deps?: { loginMethod?: LoginMethod; now?: () => number }): Promise<{ app: express.Express; close(): Promise<void> }>` builds the whole server (today's token-mode routes, or OAuth plus `/mcp`). `src/index.ts` only loads the config, calls `createApp` without `deps`, and listens. In `homeassistant` mode without an injected method it constructs Task 4's `HomeAssistantLogin`.

- [ ] **Step 1: Write failing tests in `test/oauth-ha.mjs`.** Import `createApp` from `../dist/app.js`, build it with `AUTH_MODE: "homeassistant"`, a temp `DATA_DIR`, a controllable clock, and a stub `LoginMethod` whose `start` redirects to `/login/callback?state=<loginState>&as=<name>` and whose `finish` allows `alice` and `carol` and refuses `bob`. Listen on a free port and drive the flow with plain `fetch` (`redirect: "manual"`): DCR at `/register`, `/authorize` with PKCE, follow to `/login/callback`, then `/token`. Assertions:
  - `GET /mcp without a token is 401 with a resource_metadata hint` (`WWW-Authenticate` matches `/resource_metadata=/`)
  - `discovery documents are served`: `/.well-known/oauth-authorization-server` has `issuer` equal to the public URL and lists `registration_endpoint`.
  - `an allowed person gets tokens and can list tools`: `tools/list` with the Bearer token returns 12 tools.
  - `a refused person gets a 403 page and no code`
  - `refresh rotates the token; the old one works only within 60 seconds and gives the same pair`
  - `a stale refresh after 60 seconds is rejected` (advance the injected clock)
  - `a second login for the same client and person replaces the first connection`
  - `revoking the refresh token ends the connection`
  - `connections survive a restart`: close the app and build a new one on the same `DATA_DIR`; refresh works, and the old access token gets 401.
  - `a confirmation proposed by alice cannot be committed by carol`: carol gets "Unknown or expired confirmation token", and alice can still commit it.
  - `logins are logged by name, never with a token or code`: capture `console.error` output while the tests run; it includes `alice` for a login and `bob` for a refusal, and none of the issued access, refresh or code values appear.
- [ ] **Step 2: Run `npm run build && node test/oauth-ha.mjs`.** Expected: FAIL, `createApp` not found.
- [ ] **Step 3: Implement the files above.** Move today's server setup from `src/index.ts` into `createApp`. `token` mode keeps exactly today's routes; `homeassistant` mode opens `AuthStore`, uses the injected method or Task 4's class, mounts OAuth, and serves MCP at `/mcp` behind the bearer middleware. Production code contains no test-only login switch.
- [ ] **Step 4: Run `npm test`.** Expected: all smoke, config, store and oauth checks pass.
- [ ] **Step 5: Commit** (message: "Add the OAuth provider with pluggable login methods").

### Task 4: Home Assistant login method

**Files:**
- Create: `src/auth/homeassistant.ts`
- Modify: `test/oauth-ha.mjs` (add a mock Home Assistant built with `node:http` plus `ws`), `package.json` (devDependency `ws`)

**Interfaces:**
- Consumes: `LoginMethod`, `Person` (Tasks 2–3).
- Produces: `class HomeAssistantLogin implements LoginMethod`, built with `new HomeAssistantLogin({ publicUrl, haPublicUrl, haUrl, fetch?: typeof fetch })`.
  - `start` redirects to `haPublicUrl + "/auth/authorize?response_type=code&client_id=" + publicUrl + "/&redirect_uri=" + publicUrl + "/login/callback&state=" + loginState`.
  - `finish` exchanges the code at `haUrl + "/auth/token"` (form `grant_type=authorization_code`, `code`, `client_id`), then opens `haUrl` with the `/api/websocket` path and the `ws:` scheme, authenticates with the HA access token, and sends `{"id":1,"type":"auth/current_user"}`. It requires `is_admin === true`; otherwise it revokes the HA refresh token and returns `{ refused: "Only Home Assistant administrators can connect." }`. On success: `person = { id: user.id, name: user.name }`, `upstream = { haRefreshToken }`.
  - `recheck` refreshes at `/auth/token` (`grant_type=refresh_token`) and re-reads `current_user`:
    - `400` or `invalid_grant`, or `is_admin` false → `refused`.
    - A network error, `5xx`, or a WebSocket failure → `unavailable`.
  - `cleanup` POSTs form `token=<haRefreshToken>` to `haUrl + "/auth/revoke"` and ignores failures.
  - A `GET /` on the server returns a small HTML page with `<title>LubeLogger MCP</title>`, because HA fetches the client ID URL to show the app's name.

- [ ] **Step 1: Write failing tests.** The mock HA has two users, `admin-user` (`is_admin: true`) and `plain-user` (`false`). Its `/auth/authorize?...&as=<user>` redirects straight to the given `redirect_uri` with a code. It tracks issued and revoked refresh tokens and can be told to fail with `503` or be stopped. Assertions:
  - `an HA admin connects end to end and lists tools`
  - `a non-admin is refused and their HA session is revoked` (mock: revoked count is 1)
  - `an admin login after a refused one from the same client works` (Review Focus 5)
  - `deleting the HA session ends the connection at the next refresh`: mark the HA refresh token invalid; `/token` refresh gives `400 invalid_grant`.
  - `removing admin rights ends the connection at the next refresh`
  - `HA returning 503 gives temporarily_unavailable and keeps the refresh token`: refresh gives 503; once the mock recovers, the same refresh token works.
  - `HA unreachable gives temporarily_unavailable`: with the mock stopped, as above.
  - `replacing a connection revokes the old HA session`
  - `an expired or unknown login state shows the start-again page with 400` (Review Focus 2): call `/login/callback?state=nope&code=x`; the body matches `/start again from Claude/` and doesn't match `/at .*\.js/`.
- [ ] **Step 2: Run `npm run build && node test/oauth-ha.mjs`.** Expected: FAIL, `HomeAssistantLogin` is not found.
- [ ] **Step 3: Implement `src/auth/homeassistant.ts`.** Use the global `WebSocket` and `fetch` with a 10-second timeout each.
- [ ] **Step 4: Run `npm test`.** Expected: all pass.
- [ ] **Step 5: Commit** (message: "Add the Home Assistant login method").

### Task 5: Documentation, including Cloudflare lock-down

**Files:**
- Modify: `README.md`, `.env.example`

- [ ] **Step 1:** The README's fork section and configuration table describe `AUTH_MODE`, the token mode default, and Home Assistant mode with its four variables. They state that only HA admins can connect, and that disconnecting is done in HA under Profile → Refresh tokens. The "Connect Claude" section becomes: add the plain `/mcp` URL as a custom connector, then log in to Home Assistant.
- [ ] **Step 2:** Add a section "Lock it down with Cloudflare", covering:
  - where to add the rule: Security → WAF → Custom rules;
  - the expression `(http.host eq "mcp.example.com" and not ip.src in {160.79.104.0/21 153.61.208.0/20} and not http.request.uri.path in {"/authorize" "/login" "/login/callback"})` with action Block (in token mode, drop the path clause);
  - a link to Anthropic's IP address page, and a note that the ranges can change;
  - how to check: a request from outside gets 403;
  - when it matters: optional once OAuth is on, and the main extra protection for a secret path in token mode.
- [ ] **Step 3:** Update `.env.example` with the new variables, under the existing comment style.
- [ ] **Step 4:** Run `npm test` (no regressions), then scan the README and `.env.example` for anything personal: no real domains, names, addresses or IPs other than Anthropic's published ranges. Expected: none.
- [ ] **Step 5: Commit** (message: "Document OAuth modes and Cloudflare lock-down").

### Task 6: Switch the reference Home Assistant add-on to OAuth

**Files:**
- Modify: `home-assistant/lubelogger_mcp/config.yaml`, `home-assistant/lubelogger_mcp/launch.mjs`, `home-assistant/lubelogger_mcp/Dockerfile`

**Interfaces:**
- Consumes: the env contract from Task 1.

- [ ] **Step 1:** Update `config.yaml`:
  - remove the `mcp_path` option;
  - add `public_url: url` and `home_assistant_public_url: url`, with empty defaults;
  - bump `version` to `0.4.0-<sha7>` once Task 5's commit exists.
- [ ] **Step 2:** In `launch.mjs`, as root before dropping privileges:
  - set `AUTH_MODE=homeassistant`, `HOME_ASSISTANT_URL=http://homeassistant:8123` (verified reachable from the add-on network) and `DATA_DIR=/data/oauth`;
  - create `/data/oauth` and `chown` it to `node`;
  - map the two new options to `PUBLIC_URL` and `HOME_ASSISTANT_PUBLIC_URL`.
- [ ] **Step 3:** Point the Dockerfile's `REF` at the release commit.
- [ ] **Step 4:** Commit and push to the fork's `main`. Then, outside the repo:
  1. Copy the three files to `/local_apps/lubelogger_mcp` on the HA VM.
  2. Run `ha store reload` and `ha apps update local_lubelogger_mcp`.
  3. Have the owner fill in the two URLs in the add-on's Configuration tab, and clear the old path.
  4. Check the log shows the server listening in `homeassistant` mode.
- [ ] **Step 5: Live check, with the owner.**
  1. The owner adds the browser-path exception to the Cloudflare rule.
  2. They remove the old connector and add the plain `/mcp` URL in claude.ai.
  3. They log in to Home Assistant.
  4. A new chat lists vehicles.
  5. Their HA profile shows one new refresh token, and deleting it makes the next refresh fail.
  6. The old secret URL returns 404.
