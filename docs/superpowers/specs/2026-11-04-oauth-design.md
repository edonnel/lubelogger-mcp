# OAuth login for the MCP server: design

Status: approved, 2026-11-04. Revised after an independent builder check, then widened from Home Assistant only to four login methods.

## Intent

Today the MCP endpoint's only credential is a secret segment in its URL (`/mcp/<32 hex>`). That URL is stored in the user's Claude account, seen by any proxy or tunnel that terminates TLS in front of the server (and written to some of their logs), shown in the server's configuration, and pasted wherever it gets copied. Anyone holding it can read every vehicle and record and add or edit records.

The goal is to make a leaked URL worthless: connecting Claude to LubeLogger should require a real login. For the reference deployment, a Home Assistant add-on, that login is **Home Assistant** itself, which its owner already trusts and which has its own two-factor setup. Because the fork is public, the same OAuth support should serve people without Home Assistant too, through a generic OpenID Connect provider or through LubeLogger's own accounts.

## Goals

- Claude's custom connectors (claude.ai web, desktop and phone apps) connect with a plain URL, e.g. `https://mcp.example.com/mcp`, and an OAuth login.
- **Four login methods**, one active per server, chosen in its settings (the owner's choice of methods):
  - **Home Assistant**: HA's own login page; any HA **administrator** may connect. This is what the reference Home Assistant add-on uses.
  - **OpenID Connect**: any standard OIDC provider (Google, Microsoft, Authentik, Authelia, Keycloak, Pocket ID, Zitadel, Auth0 and others), with an allowlist.
  - **LubeLogger API key**: the login page asks once for the person's own LubeLogger API key; the connection then acts with that key's permissions.
  - **LubeLogger username and password**: the login page takes the person's LubeLogger login, checked against LubeLogger.
- **Token mode stays** for people who want no OAuth (the owner's decision): the existing `MCP_AUTH_TOKEN` bearer token or secret `MCP_PATH`, unchanged. Clients that can send headers (Claude Code, Claude Desktop through `mcp-remote`) use the bearer token; claude.ai connectors can only use the secret path in this mode.
- A connection lasts while it is used and ends after **90 days without use**. Underneath, Claude holds a short-lived access token (1 hour) that it renews on its own.
- Access can be withdrawn at the source within the hour: an HA session deleted or admin rights removed, an OIDC user removed from the allowlist or the provider, a LubeLogger API key deleted, or a LubeLogger user's password changed.
- The reference add-on switches from the secret path to Home Assistant login. After the switch, the old URL stops working.

## Non-goals

- More than one login method on the same server at the same time (no "choose how to log in" page).
- GitHub login (not standard OIDC; left out by the owner's choice), and other MCP clients' OAuth quirks beyond what the MCP spec requires. Claude is the client that matters.
- Changing what the tools do. This touches only how a request is let in, and which LubeLogger key it uses.

## Anti-goals (a failure even if it "works")

- Any path that reaches LubeLogger without a valid token in the configured mode, including a leftover secret path or bearer token in an OAuth mode.
- **Privilege gain through the MCP server**: a person getting more LubeLogger rights than their own login allows, by way of the server's shared key.
- Writing passwords, API keys, tokens or authorization codes to any log.
- Storing a LubeLogger password, in any form.
- A login that leaves a growing pile of orphaned sessions at the identity provider (most visibly in an HA profile).
- Hand-rolled OAuth protocol code where the MCP SDK already provides it.

## How it works

The server is always its own OAuth 2.1 authorization server toward Claude. Only the "who are you" step differs per method.

```
Claude                     MCP server                                 Login method
  | GET /mcp (no token) -> 401 + where to log in
  | discovery (/.well-known/...) and dynamic client registration
  | user's browser -> /authorize ------------------------------------> identify the person:
  |                                                                      HA:      redirect to HA login, back to /login/callback
  |                                                                      OIDC:    redirect to the provider, back to /login/callback
  |                                                                      LL key:  form on /login asking for the API key
  |                                                                      LL pass: form on /login asking for username + password
  |                    allowed?  no -> plain "not allowed" page (and clean up any session it created)
  |                              yes -> issue an MCP authorization code back to Claude
  | /token: code -> access token (1 h) + refresh token
  | /mcp with Bearer access token -> tools, using the connection's LubeLogger key
  | /token refresh (hourly): re-check the person with the login method, then issue a new access token
```

### Decided: shared core

- **Built on the MCP SDK's server-auth framework** (`mcpAuthRouter`, `OAuthServerProvider`, `requireBearerAuth` in `@modelcontextprotocol/sdk` 1.32.1): metadata discovery, dynamic client registration, PKCE, token and revocation endpoints come from the SDK. The fork implements one provider with a small, pluggable "login method" interface: start a login, finish it (returning a person or a refusal), re-check a person on refresh, and clean up.
- **Mode selection.** `AUTH_MODE` is `token` (the default, today's behaviour), `homeassistant`, `oidc`, `lubelogger-key` or `lubelogger-password`. In any OAuth mode the endpoint is fixed at `/mcp` and needs an OAuth access token, and **the server refuses to start if `MCP_AUTH_TOKEN` or a custom `MCP_PATH` is also set** (my call): a leftover static credential would reopen a way in that skips the login.
- **Tokens.** Access tokens are random and kept in memory only (1 hour), so a restart only forces a silent refresh. MCP refresh tokens are random, stored **hashed** in the server's data folder (`/data` in the add-on), rotated on each use, and expire after 90 days unused. Anything a login method must keep usable (an HA or OIDC refresh token, a LubeLogger API key) is stored in that folder too, private to the server and included in HA backups for the add-on.
- **Connections** (my call, from the builder check). A connection is one OAuth client (one Claude account or app) for one person, so several are allowed. A new login from the same client and person replaces the old connection and cleans up its upstream session. A connection is also cleaned up when Claude calls `/revoke`, when its refresh token expires, and when a login is refused. No upstream session outlives its connection.
- **Login method unreachable during a refresh** (my call). Network errors and 5xx answers from the login method make the token endpoint return a temporary error (HTTP 503, `temporarily_unavailable`) without consuming the refresh token, so Claude can retry and nobody has to log in again because HA, the OIDC provider or LubeLogger restarted. A token is never issued without a successful re-check. Only a definite refusal ends the connection.
- **Pending confirmations are scoped to the person** (my call). A preview's confirmation token can only be committed by the same person who proposed it. In token mode there is a single identity and behaviour is unchanged.
- **Logging** (my call). Logins, refusals and disconnections are logged with the person's name or username, never with a token, code, key or password.
- **Login pages** for the two LubeLogger methods are served by the server itself: plain HTML forms, no third-party assets, protected against cross-site request forgery, and **rate-limited per person and per address** (my call; LubeLogger does not limit login attempts itself).
- **Firewall (optional, deployments behind Cloudflare).** A Cloudflare WAF rule that admits only Anthropic's published outbound ranges is recommended defense in depth: once OAuth is on, a leaked URL is useless without a login, so the rule is no longer what keeps strangers out, but it keeps scanners and junk client registrations away from the login code and limits the damage of any bug in it. It needs an exception for the browser paths: `/authorize`, `/login` and `/login/callback`. Everything else stays Anthropic-only, unless testing shows Claude makes one of those calls from the browser, in which case that one path is added.
- **Cloudflare instructions live in the setup docs** (the owner's decision), not on any page the server serves. The README gets a "Lock it down with Cloudflare" section: where to add a WAF custom rule, the exact expression with a placeholder hostname, the browser-path exception for OAuth modes, and how to check it (a request from outside Anthropic's ranges gets 403). It also says plainly that the rule is optional once an OAuth mode is on, and that in token mode with a secret path it is the main protection beyond the URL itself. Anthropic's published outbound ranges are cited with a link, since they can change.

### Decided: per login method

**Home Assistant** (`AUTH_MODE=homeassistant`)
- HA's IndieAuth-style OAuth. Client ID is the server's public origin plus `/`; redirect URI is `<public origin>/login/callback`, on the same host, which HA accepts (`homeassistant/components/auth/indieauth.py`, verified).
- After the code exchange, the server calls `auth/current_user` over HA's WebSocket API and requires `is_admin: true` (field verified in `homeassistant/components/auth/__init__.py`).
- The HA refresh token is kept; each hourly refresh renews the HA session and re-checks `is_admin`. Deleting the session in the HA profile (Refresh tokens) or removing admin rights ends the connection within the hour. Cleanup revokes the HA session with HA's `/auth/revoke`.
- LubeLogger calls use the server's shared key.

**OpenID Connect** (`AUTH_MODE=oidc`)
- Standard authorization code flow with PKCE against the provider found through its issuer's discovery document. Requested scopes: `openid email profile` plus `offline_access` where the provider supports it.
- **Allowlist (required, my call):** one or more of allowed emails (only when the provider marks the email verified), allowed subject IDs, or a required group in a configurable claim. No allowlist means the server refuses to start, so "anyone with a Google account" can never connect by accident.
- Each hourly refresh renews the provider session with its refresh token and re-checks the allowlist against the fresh claims. If the provider issues no refresh token, the connection ends at the provider's ID-token lifetime and Claude must log in again.
- LubeLogger calls use the server's shared key.

**LubeLogger API key** (`AUTH_MODE=lubelogger-key`)
- The login page asks for the person's own LubeLogger API key. The server checks it by calling LubeLogger with it (`x-api-key`, an API LubeLogger supports per user).
- **The connection uses that key for every LubeLogger call**, so each person gets exactly their own LubeLogger permissions and the server needs no shared key in this mode. Deleting the key in LubeLogger ends the connection at the next refresh.
- Anyone with a valid key for this LubeLogger may connect; the key itself is the permission.

**LubeLogger username and password** (`AUTH_MODE=lubelogger-password`)
- The login page takes a LubeLogger username and password and checks them with LubeLogger's API (HTTP Basic, supported in `Middleware/Authen.cs`). The password is used once for that check and **never stored**.
- **Allowlist of LubeLogger usernames (required, my call).** The server cannot act with the person's own rights without keeping their password, so it uses its shared key; the allowlist keeps a low-permission LubeLogger account from gaining the shared key's rights. Without an allowlist the server refuses to start.
- Re-check on refresh: since no password is kept, the connection simply lasts until its 90-day idle expiry or a revoke; removing a username from the allowlist ends it at the next refresh. (A password change in LubeLogger does not end it, and the documentation says so.)

### Configuration

Environment variables (server), with the add-on option where one exists:

- `LUBELOGGER_URL` (`lubelogger_url`): unchanged.
- `LUBELOGGER_API_KEY` (`lubelogger_api_key`): the shared key; required in every mode except `lubelogger-key`.
- `AUTH_MODE`: `token` (default), `homeassistant`, `oidc`, `lubelogger-key`, `lubelogger-password`. The reference add-on sets `homeassistant`.
- `PUBLIC_URL` (`public_url`): the server's public origin, required in every OAuth mode.
- Home Assistant: `HOME_ASSISTANT_PUBLIC_URL` (`home_assistant_public_url`), and `HOME_ASSISTANT_URL` for server-to-HA calls (set by the add-on's launcher, not an option).
- OIDC: `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`, and at least one of `OIDC_ALLOWED_EMAILS`, `OIDC_ALLOWED_SUBJECTS`, or `OIDC_REQUIRED_GROUP` with `OIDC_GROUPS_CLAIM` (default `groups`).
- LubeLogger password: `LUBELOGGER_ALLOWED_USERS`.
- Token mode only: `MCP_AUTH_TOKEN`, `MCP_PATH`. The add-on's `mcp_path` option is removed.

### Delivery (my call)

Three releases, each tested and deployable on its own:

1. The shared core plus **Home Assistant** login, and the reference add-on switched over.
2. **OpenID Connect**.
3. The two **LubeLogger** login methods.

### Left to the builder

- The internal Home Assistant address an add-on uses to reach Core, verified on the live VM.
- Exact storage format and file locking for the data folder, and making it writable by the unprivileged `node` user after `launch.mjs` drops privileges.
- Page wording for login forms, "not allowed" and errors, in plain language.
- Whether the SDK's built-in PKCE, client store and rate limiting need configuration; `trust proxy` behind the tunnel; persisting dynamically registered clients across restarts.
- Test strategy: a mock for each login method (mock HA, mock OIDC provider, the existing mock LubeLogger extended with key and Basic checks) covering allowed, refused, revoked at source, unreachable during refresh, re-login replacing a connection and expired token cases; the token-mode tests keep running; and for the reference add-on a live end-to-end connect from claude.ai before the old connector is removed.
