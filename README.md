# lubelogger-mcp

## About this fork

This is a fork of [drakebridgewater/lubelogger-mcp](https://github.com/drakebridgewater/lubelogger-mcp), branched from upstream commit `e182246` (2026-10-19), which was reviewed in full before forking. Upstream declares the MIT license in `package.json`; it has no LICENSE file.

Every request it sends was checked against the LubeLogger 1.7.4 source: routes, field names, JSON converters and required fields. Like upstream, it has not yet been run against a live instance.

### Changes from upstream

- **Refuses to start without a credential.** If `MCP_AUTH_TOKEN` is not set, `MCP_PATH` must contain a random segment of at least 32 characters, e.g. `/mcp/<output of: openssl rand -hex 16>`. Upstream printed a warning and served the endpoint to anyone who could reach it.
- **Keeps a custom `MCP_PATH` out of the log.** Upstream printed it in its startup line, and for clients that cannot send a bearer token (the Claude app) that path is the only credential.
- **Patched dependencies**, lockfile only: `body-parser` 2.4.0 ([GHSA-27r3-jxmh-p828](https://github.com/advisories/GHSA-27r3-jxmh-p828), denial of service) and `fast-uri` 3.1.9 ([GHSA-w74x-v6f9-j3xg](https://github.com/advisories/GHSA-w74x-v6f9-j3xg) and related).
- **Sign in with Home Assistant (OAuth).** With `AUTH_METHODS=homeassistant`, the Claude app connects through a plain `https://<host>/mcp` URL and a Home Assistant login instead of a secret path. `AUTH_METHODS` is a list of sign-in methods, so more can be added alongside it; `AUTH_MODE=homeassistant` still works and means the same thing. Only Home Assistant admins (`is_admin`) can connect. See [Sign in with Home Assistant](#sign-in-with-home-assistant-oauth). With neither set, `AUTH_MODE` defaults to `token`, the behaviour above.
- **Sign in with OpenID Connect.** Add `oidc` to `AUTH_METHODS` to let people sign in with any standard OpenID Connect provider (Google, Authentik, Keycloak and so on). It can run alongside Home Assistant, as a second button on the same sign-in screen. See [Sign in with OpenID Connect](#sign-in-with-openid-connect).
- **Sign in with LubeLogger.** Add `lubelogger-password` and/or `lubelogger-key` to `AUTH_METHODS` to let people sign in with their LubeLogger username and password, or with their own LubeLogger API key. They share the sign-in screen with the other methods. See [Sign in with LubeLogger](#sign-in-with-lubelogger).
- Tests for all of the above in `test/smoke.mjs`, and a `.gitattributes` that keeps line endings LF.
- **Follows LubeLogger's "Odometer Optional" setting.** Service, repair, upgrade and fuel records for those vehicles can leave the odometer out; it is saved as 0, which LubeLogger shows as a blank odometer, matching its own form. `list_vehicles` marks these vehicles, and Claude treats the reading as a suggestion for them. Upstream required it for every vehicle.
- **Edits existing records.** `list_records` finds them and `propose_record_update` changes only the fields given, through the same preview-and-confirm flow. LubeLogger's update endpoints overwrite every field, so the update starts from the full record and keeps attachments, extra fields and fuel charge levels. Upstream was add-only.
- **Itemized Markdown notes.** LubeLogger records have no line items, so Claude writes notes in Markdown laid out like the invoice: facts as a list, line items as a table in the invoice's own columns, totals as a list. The format follows the rules of LubeLogger's renderer (`drawdown`), and the notes limit is raised to 10,000 characters. Turn on **Use Markdown on Saved Notes** in LubeLogger's settings to see it rendered.
- A Home Assistant local add-on in `home-assistant/lubelogger_mcp/`. Copy the folder to `/local_apps/` on the HA host. It builds the commit pinned as `REF` in its `Dockerfile`, reads its settings from the add-on's Configuration tab, and drops to the unprivileged `node` user before starting.

### Pulling changes from upstream

Upstream has one maintainer and its changes have not been reviewed here, so pull them deliberately, never automatically:

```bash
git fetch upstream
git log --oneline main..upstream/main   # what's new
git diff main...upstream/main           # read it before merging
git merge upstream/main
npm ci && npm test
```

In a fresh clone, add the remote first, with pushing disabled so nothing can be pushed to upstream by mistake:

```bash
git remote add upstream https://github.com/drakebridgewater/lubelogger-mcp.git
git remote set-url --push upstream DISABLED
```

## Overview

An [MCP](https://modelcontextprotocol.io) server that lets Claude log service, repair, upgrade, fuel and odometer records into your self-hosted [LubeLogger](https://github.com/hargata/lubelog), and manage maintenance reminders.

You send Claude a photo or PDF of an invoice or receipt. Claude reads it, extracts the fields, shows you a preview, and after you confirm, writes the record to LubeLogger.

The server does **no** OCR or document parsing. Claude already reads images and PDFs, so the server is a thin, typed, validated wrapper over the LubeLogger API.

## How it works

```
photo/PDF  ->  Claude reads it  ->  propose_* tool  ->  PREVIEW + warnings + token
                                                              |
                                      you confirm in chat  <--'
                                              |
                                      commit_record(token)  ->  LubeLogger API
```

- **Nothing is written by a `propose_*` tool.** It validates, resolves the vehicle, compares against the latest odometer, checks for duplicates, and stores the exact payload under a single-use token (default 30 min).
- **`commit_record` writes exactly what was previewed**, not re-derived input.
- **Odometer is required unless the vehicle has "Odometer Optional" on.** Receipts usually lack it, so Claude asks you for it, typed or as a photo of the dashboard. For odometer-optional vehicles it can be left out and is saved as 0, as LubeLogger's own form does.

## Tools

| Tool | Purpose |
|---|---|
| `list_vehicles` | Vehicles with ids and latest odometer |
| `get_latest_odometer` | Latest odometer for one vehicle |
| `propose_service_record` | Service, repair or upgrade record (`recordType`), from an invoice or work order |
| `propose_fuel_record` | Fuel or EV charge, from a receipt (supports partial fills, missed fill-ups, EV state of charge) |
| `propose_odometer_record` | Standalone odometer reading (e.g. from a dashboard photo) |
| `list_reminders` | A vehicle's reminders with id, urgency, due date/odometer and what's left |
| `propose_reminder` | New reminder due at a date, an odometer reading, or both (whichever comes first) |
| `propose_reminder_update` | Change an existing reminder by id, e.g. move "Rotate Tires" forward after a rotation. Unspecified fields are kept |
| `list_records` | A vehicle's records of one type, newest first, with id, date, odometer, cost and attachment count |
| `get_record` | One record in full: every field, the complete notes, attachment names and extra fields |
| `propose_record_update` | Correct an existing service, repair, upgrade, fuel or odometer record by id. Only the given fields change; attachments and everything else are kept |
| `commit_record` | Save a previously proposed record or reminder by token |

Vehicles can be referenced by id or any part of the name/plate (`tacoma`, `ABC123`). If a name matches more than one vehicle, the tool errors and Claude asks you.

### Warnings shown in previews

- Odometer lower than the latest reading on file (likely misread), or an unusually large jump (extra digit)
- Possible duplicate (same date and same odometer or cost, for that record type)
- Date in the future
- Fuel: implausible price per unit or quantity (amount/cost swapped, wrong units)
- Reminders: a similar reminder already exists (so Claude offers an update instead of a duplicate), the due date or odometer is already past, or an update changes nothing

## Setup

### 1. Create a LubeLogger API key

In LubeLogger, open the user menu and create an API key. The **Editor** role (view, add, edit) is enough. Don't give it Manager.

### 2. Configure

```bash
cp .env.example .env
# fill in LUBELOGGER_API_KEY, and set MCP_AUTH_TOKEN (openssl rand -hex 24)
```

| Variable | Default | Notes |
|---|---|---|
| `LUBELOGGER_URL` | required | Address of LubeLogger as seen from this container, e.g. `http://lubelogger:8080` |
| `LUBELOGGER_API_KEY` | required | Sent as the `x-api-key` header. Optional only when `lubelogger-key` is the only method in `AUTH_METHODS`, because every connection then uses its owner's own key |
| `MCP_AUTH_TOKEN` | unset | If set, every MCP request needs `Authorization: Bearer <token>`. If unset, `MCP_PATH` must hold a secret segment or the server will not start |
| `MCP_PATH` | `/mcp` | Without `MCP_AUTH_TOKEN`, must contain a random segment of at least 32 characters, e.g. `/mcp/<output of: openssl rand -hex 16>`. A custom path is never printed in the log |
| `AUTH_METHODS` | unset | Comma-separated sign-in methods for OAuth: `homeassistant`, `oidc`, `lubelogger-password` and `lubelogger-key`. Any of them can be on together, and the sign-in screen offers each one. Never set it together with a non-token `AUTH_MODE` |
| `AUTH_MODE` | `token` | `token` is the bearer token or secret path above. `homeassistant` still works and means `AUTH_METHODS=homeassistant`. Setting `AUTH_METHODS` together with a non-token `AUTH_MODE` refuses to start |
| `PUBLIC_URL` | unset | Required when a sign-in method is on. This server's public address, origin only with no path, e.g. `https://mcp.example.com` |
| `HOME_ASSISTANT_PUBLIC_URL` | unset | Home Assistant mode only, required. Home Assistant's address as your browser sees it, no path, e.g. `https://ha.example.com` |
| `HOME_ASSISTANT_URL` | unset | Home Assistant mode only, required. Home Assistant's address as this server reaches it, no path, e.g. `http://homeassistant:8123` inside the add-on network |
| `DATA_DIR` | `./data` | Sign-in modes. Holds `oauth.json` with the registered clients and connections. Keep it private and back it up |
| `ALLOWED_REDIRECT_HOSTS` | `claude.ai,claude.com` | Sign-in modes. Hosts a login code may be sent back to, comma-separated bare hostnames with no scheme or port. Only these hosts can register as clients. Add `localhost,127.0.0.1` for Claude Code |
| `LUBELOGGER_ALLOWED_USERS` | unset | Comma-separated LubeLogger usernames that may sign in with `lubelogger-password`. Required when that method is on. See [Sign in with LubeLogger](#sign-in-with-lubelogger) |
| `OIDC_*` | see below | The OpenID Connect settings, listed under [Sign in with OpenID Connect](#sign-in-with-openid-connect) |
| `PORT` / `HOST` | `3000` / `0.0.0.0` | |
| `CONFIRM_TTL_MINUTES` | `30` | How long a preview token stays valid |
| `REQUEST_TIMEOUT_MS` | `15000` | Timeout for LubeLogger calls |

### 3. Run with Docker next to LubeLogger

See `docker-compose.example.yml`. Either add the `lubelogger-mcp` service to your existing LubeLogger compose file (simplest, then `LUBELOGGER_URL=http://lubelogger:8080` works as-is), or attach it to LubeLogger's network.

```bash
docker compose up -d --build
curl http://localhost:3000/healthz   # {"status":"ok"}
```

Without Docker: `npm ci && npm run build && npm start` (Node 22.4 or newer, which provides the global `WebSocket` the Home Assistant mode uses).

### 4. Connect Claude

**Claude Code**, token mode (works for anything on your LAN or Tailscale):

```bash
claude mcp add --transport http lubelogger http://<server>:3000/mcp \
  --header "Authorization: Bearer <MCP_AUTH_TOKEN>"
```

In Home Assistant mode there is no bearer token: Claude Code signs in through OAuth like the app does. See [Claude Code in Home Assistant mode](#claude-code-in-home-assistant-mode).

**Claude app / claude.ai custom connector:** as far as I know, remote connectors are called from Anthropic's cloud, not from your phone or LAN. That means the URL must be reachable over public HTTPS (reverse proxy, Cloudflare Tunnel, Tailscale Funnel). Check Anthropic's current connector docs before relying on this, since it changes. The connector UI doesn't take a static bearer header (it supports OAuth or none), so there are two routes:

- **Home Assistant sign-in (recommended).** Set `AUTH_METHODS=homeassistant`, as described next. The connector URL is the plain `https://mcp.example.com/mcp`, and you log in to Home Assistant when you connect.
- **Secret path.** In the default `token` mode, set `MCP_PATH` to a long random path and treat that URL as a secret.

## Sign in with Home Assistant (OAuth)

With `AUTH_METHODS=homeassistant` this server is its own OAuth server and uses Home Assistant to prove who you are. There is no bearer token and no secret path to protect. (`AUTH_MODE=homeassistant` still works and means the same thing, but don't set both.)

Set these in `.env` (or the add-on's Configuration tab):

```env
AUTH_METHODS=homeassistant
PUBLIC_URL=https://mcp.example.com
HOME_ASSISTANT_PUBLIC_URL=https://ha.example.com
HOME_ASSISTANT_URL=http://homeassistant:8123
```

- The endpoint is fixed at `/mcp`. The server refuses to start if `MCP_AUTH_TOKEN` or a custom `MCP_PATH` is also set.
- `PUBLIC_URL` and `HOME_ASSISTANT_PUBLIC_URL` are what a browser sees. `HOME_ASSISTANT_URL` is what this server uses to talk to Home Assistant, so inside the add-on network it can be a plain internal address.
- Besides `/mcp`, the server answers the OAuth endpoints that Claude's servers call (`/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource/mcp`, `/register`, `/token` and `/revoke`) and the browser paths `/authorize`, `/login` and `/login/callback`. All of them must be reachable through your reverse proxy or tunnel.
- `DATA_DIR` holds `oauth.json`, the registered clients and connections. Keep it private and back it up. Losing it means every connection has to be made again.
- Node 22.4 or newer is required (the global `WebSocket`).

**Connect Claude.**

1. In Claude, add a custom connector with the plain URL `https://mcp.example.com/mcp`.
2. A sign-in screen on this server, titled "Sign in to LubeLogger MCP", names the app and the host it returns to, and says "Only continue if you started this from Claude." Press **Continue with Home Assistant**. Pressing it counts as approving; there is no separate Approve step.
3. Log in to Home Assistant. Claude is connected.

The sign-in screen has one button per method that is switched on. Only Home Assistant admins (`is_admin`) can connect. Access tokens last 1 hour and Claude renews them in the background. A connection stays until it has gone 90 days without use.

**Disconnect.** In Home Assistant, open Profile, then Refresh tokens, and delete the entry. The connection ends at the next hourly refresh. A user who loses admin rights is disconnected at the next refresh too. If Home Assistant is unreachable at that moment, Claude is told to try again later and the connection is kept.

**If it stops working for everyone.** Home Assistant's IP ban (`ip_ban_enabled`) is the one thing to watch: if it ever banned this server's address, every connection would end at its next refresh.

**Switching a method off.** While the server still has other methods on, connections made with a method that has been switched off are removed, at the next start or at their next refresh, whichever comes first. If the switched-off method's settings are still in place, the server also revokes its sessions at the source (for Home Assistant the refresh token, for OpenID Connect the refresh token when the provider has a revocation endpoint), so there is nothing left to delete there. If the settings are gone, it cannot reach the source and does not try, so delete those sessions yourself. For Home Assistant that is Profile, then Refresh tokens. If the method you switch off is the only one on, the server goes back to token mode, which leaves the sign-in data alone: existing connections stay in the data file and work again if the method is switched back on within 90 days. The add-on will not start with no method switched on.

The startup log says which methods are on, for example `lubelogger-mcp listening on http://0.0.0.0:3000, endpoint /mcp, auth homeassistant,oidc`, or ends in `auth token` in token mode.

### Upgrading the add-on from 0.4 to 0.5

Version 0.5 needs no new settings, so the update starts as it is. It adds a **homeassistant** checkbox, on by default, which is the sign-in method you already use. The add-on's launcher now also checks `public_url` and `home_assistant_public_url`: if one is missing, it names the option in the log without printing any values.

### Upgrading the add-on from 0.3.x

Version 0.4 switches the add-on to Home Assistant sign-in. It adds two required options, `public_url` and `home_assistant_public_url`, and drops `mcp_path`. The old version's settings form can't hold the new options, so they can only be filled in after the update, and the add-on stays stopped until they are:

1. Take a backup of the add-on (Settings → System → Backups, partial, this add-on only). Restoring it brings back the secret-path version.
2. Update. The Supervisor installs the new version, then refuses to start it with "invalid options: Missing option 'public_url'".
3. On the Configuration tab, fill in `public_url` (this server's public address, e.g. `https://mcp.example.com`) and `home_assistant_public_url` (e.g. `https://ha.example.com`), save, and start the add-on. The old `mcp_path` is removed when you save.
4. If you use the Cloudflare rule, add the sign-in path exception described [below](#lock-it-down-with-cloudflare).
5. In Claude, remove the old connector and add the plain `https://mcp.example.com/mcp` URL. The old secret path now answers 404.

**Watch the error in step 2.** The Supervisor's "invalid options" message repeats every current option, the LubeLogger API key and the old secret path included, and it lands in the Supervisor log. If anyone else can read that output, create a new LubeLogger API key, put it in the add-on, and delete the old one.

### Claude Code in Home Assistant mode

Claude Code connects through the same OAuth sign-in, with the plain URL and no header:

```bash
claude mcp add --transport http lubelogger https://mcp.example.com/mcp
```

Two things differ from the Claude app:

- Claude Code receives the login on `http://localhost:<port>` on your own machine, so those hosts must be allowed: `ALLOWED_REDIRECT_HOSTS=claude.ai,claude.com,localhost,127.0.0.1` (in the add-on, the `allowed_redirect_hosts` option). Entries are bare hostnames, with no scheme or port.
- Claude Code calls the server from your machine, not from Anthropic's cloud, so it does not work with the Anthropic-only Cloudflare rule below. Use one or the other.

## Sign in with OpenID Connect

OpenID Connect (OIDC) lets people sign in with an account at a provider you already use, such as Google, Authentik, Keycloak or Authelia. Add `oidc` to `AUTH_METHODS`, on its own or next to `homeassistant`. With both on, the sign-in screen shows one button for each and the person picks. The rest of the flow, the connector URL and the 1-hour access tokens are the same as for Home Assistant.

```env
AUTH_METHODS=oidc
PUBLIC_URL=https://mcp.example.com
OIDC_ISSUER=https://idp.example.com/realms/home
OIDC_CLIENT_ID=lubelogger-mcp
OIDC_ALLOWED_EMAILS=alice@example.com
```

| Variable | Default | Notes |
|---|---|---|
| `OIDC_ISSUER` | required | The provider's address, e.g. `https://idp.example.com/realms/home`. It may have a path. It must be `https`; plain `http` is accepted only for `localhost` and `127.0.0.1`, for testing |
| `OIDC_CLIENT_ID` | required | The client id the provider gave you |
| `OIDC_CLIENT_SECRET` | unset | The client secret, if the client is confidential. Leave it out for a public client |
| `OIDC_DISPLAY_NAME` | `single sign-on` | The name on the sign-in button |
| `OIDC_ALLOWED_EMAILS` | unset | Comma-separated emails that may sign in. An email counts only if the provider marks it verified (`email_verified` is true) |
| `OIDC_ALLOWED_SUBJECTS` | unset | Comma-separated subject ids (the `sub` claim) that may sign in |
| `OIDC_REQUIRED_GROUP` | unset | A group whose members may sign in |
| `OIDC_GROUPS_CLAIM` | `groups` | The ID token claim that lists a person's groups |
| `OIDC_AUTH_PARAMS` | unset | Extra query parameters added to the sign-in request, e.g. `access_type=offline&prompt=consent` |

**Who may sign in.** At least one of `OIDC_ALLOWED_EMAILS`, `OIDC_ALLOWED_SUBJECTS` and `OIDC_REQUIRED_GROUP` is required, and the server refuses to start with none of them, so "anyone with an account at the provider" is never the default. A person is allowed if any one of them matches. An email in `OIDC_ALLOWED_EMAILS` matches only when the provider says it is verified. The server always verifies the ID token's signature.

**Register the client at the provider.**

1. Create an OpenID Connect client (sometimes called an application). A confidential client with a secret or a public client both work.
2. Set its redirect URI to `https://mcp.example.com/login/callback`, where the host is your `PUBLIC_URL`.
3. Allow the `openid`, `email` and `profile` scopes. For `OIDC_REQUIRED_GROUP`, make sure the provider puts groups in the ID token under the claim named by `OIDC_GROUPS_CLAIM`.

   The server reads claims from the ID token only, never from the userinfo endpoint, so the email (with `email_verified`) and the groups claim must be in the ID token. Some providers put them only in userinfo by default; an allowlist on a claim that is missing from the ID token refuses everyone.
4. Copy the client id (and the secret, if any) into the settings above.

**Refresh tokens.** The connection stays alive by refreshing at the provider every hour, which needs a refresh token. A provider that issues none ends the connection when the ID token it started with expires, typically within the hour, and the person signs in again. Google only issues a refresh token when asked for one, so set

```env
OIDC_AUTH_PARAMS=access_type=offline&prompt=consent
```

Each refresh checks the allowlist again against the new ID token, so removing someone from `OIDC_ALLOWED_EMAILS`, or from the group, disconnects them at their next refresh, provided the provider returns a new ID token on that refresh. A provider that refreshes without one leaves the old ID token's claims standing until that ID token expires, and the removal takes effect then. If the provider completes a refresh but the answer is lost on the way, for example by a timeout, the retry is refused and the person signs in again.

**Disconnect.** When a connection ends, the server revokes its refresh token at the provider, if the provider has a revocation endpoint. Without one, end the session at the provider.

**In the Home Assistant add-on.** Tick the **oidc** checkbox (it is off by default) and fill in the `oidc_*` options, which match the variables above: `oidc_issuer`, `oidc_client_id`, `oidc_client_secret`, `oidc_display_name`, `oidc_allowed_emails`, `oidc_allowed_subjects`, `oidc_required_group`, `oidc_groups_claim` and `oidc_auth_params`. The add-on will not start while the checkbox is on and the issuer, the client id or all three allowlist options are missing; it names the option in the log without printing values.

## Sign in with LubeLogger

Two more methods let people sign in with LubeLogger itself, with no Home Assistant or identity provider needed. Add either or both to `AUTH_METHODS`:

- `lubelogger-password`: the person types their LubeLogger username and password.
- `lubelogger-key`: the person pastes their own LubeLogger API key.

```env
AUTH_METHODS=lubelogger-password,lubelogger-key
PUBLIC_URL=https://mcp.example.com
LUBELOGGER_ALLOWED_USERS=alice,bob
```

On the sign-in screen the password form comes after any buttons for the other methods. When the key method is on too, it sits under the password form behind "Use a LubeLogger API key instead"; on its own it is shown directly.

**LubeLogger's own login must be on.** If LubeLogger runs with its login switched off, every attempt is refused, because there is no way to tell who is signing in.

**Who may sign in.**

- **Password:** `LUBELOGGER_ALLOWED_USERS` is required when `lubelogger-password` is on, and the server refuses to start without it. A person is the username LubeLogger reports for them, not what they typed. Every refresh checks the list again, so removing someone disconnects them at their next refresh.
- **API key:** there is no list. Anyone with a valid LubeLogger API key can connect, so hand out keys with that in mind.

**Whose permissions it uses.** A connection made with an API key acts with that person's own LubeLogger permissions: every LubeLogger call it makes uses their key. A connection made with a password uses the shared `LUBELOGGER_API_KEY`, like the other methods.

**Ending a connection.**

- **API key:** deleting the key in LubeLogger ends the connection at its next refresh.
- **Password:** changing the person's password does not end the connection, because the server never stores it. Take the person out of `LUBELOGGER_ALLOWED_USERS`.
- Ending a connection never deletes anyone's key in LubeLogger.

**Passwords with a colon can't sign in.** LubeLogger's API checks a password through basic authentication, which cannot carry a `:` in the username or the password. A person whose password has one needs another method, or a new password.

**Too many attempts.** 5 failed sign-ins within 15 minutes lock the address they came from for up to 15 minutes. An IPv6 address counts as its whole /64 network, since one client can use any address in it. On the password form the username is locked too, whichever address the guesses come from, so spreading guesses over many addresses or networks doesn't get more than 5 tries at one username. Attempts still being checked count as failures until they finish. Correct credentials for someone who is not on the allowlist don't count as failures, and are still refused. A locked-out person sees "Too many attempts" and can try again when the time is up.

- **The address comes from the proxy in front.** The server trusts exactly one reverse proxy or tunnel in front of it (Express's `trust proxy 1`) and takes the client's address from the `X-Forwarded-For` header that proxy sets. Without a proxy in front, a client can choose its own address, and only the username lock is left.
- **During a flood of failed attempts**, the server stops tracking new addresses and usernames once it holds as many as it can, and the two LubeLogger forms refuse sign-ins from any address or username it is not already tracking until the flood subsides. Home Assistant and OIDC sign-in keep working throughout.

**Spell usernames the way LubeLogger does.** `LUBELOGGER_ALLOWED_USERS` is compared with the username LubeLogger reports, exactly, including case: write `alice` if LubeLogger knows her as `alice`, not `Alice`.

**`LUBELOGGER_API_KEY` when only the key method is on.** With `lubelogger-key` as the only method, nobody uses the shared key, so `LUBELOGGER_API_KEY` may be left out. With any other method on, it is still required.

**In the Home Assistant add-on.** Tick the **lubelogger_password** and/or **lubelogger_key** checkboxes (both are off by default). For passwords, fill in `lubelogger_allowed_users`. `lubelogger_api_key` may be blank only when **lubelogger_key** is the only method ticked. The add-on will not start while a ticked method is missing a setting; it names the option in the log without printing values.

## Lock it down with Cloudflare

If the server is public through Cloudflare, you can have Cloudflare refuse requests that do not come from Anthropic's cloud, apart from the browser sign-in paths. It is optional once OAuth is on, because the sign-in already protects `/mcp`. In token mode with a secret path it is the main extra protection, since the path is the only credential. It rules out Claude Code, which calls from your own machine.

In the Cloudflare dashboard, open the zone, then **Security → WAF → Custom rules**, and create a rule with action **Block** and this expression (replace `mcp.example.com` with your host):

```
(http.host eq "mcp.example.com" and not ip.src in {160.79.104.0/21 153.61.208.0/20} and not http.request.uri.path in {"/authorize" "/login" "/login/callback"})
```

- The two ranges are Anthropic's published addresses, listed on [Anthropic's IP addresses page](https://docs.anthropic.com/en/api/ip-addresses). They can change, so check that page again if Claude stops reaching the server.
- The OAuth endpoints that Claude's servers call (`/.well-known/…`, `/register`, `/token`, `/revoke`) come from Anthropic's addresses, so the IP clause already lets them through.
- The path clause leaves the browser sign-in paths open, because you reach them from your own browser. In token mode there is no sign-in, so drop the last clause: `(http.host eq "mcp.example.com" and not ip.src in {160.79.104.0/21 153.61.208.0/20})`.
- Your OpenID Connect provider needs no exception. This server calls the provider itself, so the provider never has to reach it through the rule, and your browser reaches the provider directly and returns to `/login/callback`, which the path clause already allows.
- To check it, request the connector URL from outside, for example `curl -i https://mcp.example.com/mcp` from your own machine. It should answer 403. Connecting from Claude should still work.

## Security notes

- This server holds an API key that can add records to your LubeLogger, so it refuses to start without either `MCP_AUTH_TOKEN`, a secret `MCP_PATH`, or an OAuth `AUTH_METHODS`. Keep it LAN/VPN-only where you can.
- The confirm-before-write step is enforced as a two-call flow (propose, then commit with a token). That "the user said yes" is Claude's judgment, guided by the tool descriptions. The Claude app's own tool-approval prompt is a second gate if you leave it on for `commit_record`.
- Costs and amounts are plain numbers in whatever currency and unit LubeLogger is configured for. No conversion happens.

## Limitations

- Records and reminders can be added and edited but not deleted (do that in the LubeLogger UI).
- LubeLogger's API doesn't expose a reminder's recurring settings. Updates leave them as they are; set recurrence in the UI.
- The original invoice/receipt isn't attached to the record. LubeLogger has `/api/documents/upload` and a per-record `files` field, so this is a feasible follow-up.
- Pending previews live in memory, so a container restart drops them (just propose again).
- Tax and planner records aren't covered yet.
- Written against LubeLogger's published API definition (`wwwroot/defaults/api.json` on `main`) and tested end-to-end against a mock of it. It has **not** been run against a live instance. See the first-run checklist.

## First-run checklist

1. Ask Claude to run `list_vehicles`. You should see both vehicles with their latest odometer.
2. Send a receipt photo for a record you don't mind deleting (or a standalone odometer reading), confirm it, and check it in LubeLogger.
3. Delete the test record in the UI.

If the write fails with 401/403, check the API key role. If vehicles come back empty, the key's user may not have access to them.

## Development

```bash
npm run build
npm test      # builds, then runs an end-to-end smoke test (real server + MCP client + mock LubeLogger)
```

## LubeLogger endpoints used

`GET /api/vehicles`, `GET /api/vehicle/odometerrecords/latest`, `GET /api/vehicle/{servicerecords|repairrecords|upgraderecords|gasrecords|odometerrecords}` (duplicate check), `POST /api/vehicle/{...}/add`, `GET /api/vehicle/reminders`, `POST /api/vehicle/reminders/add`, `PUT /api/vehicle/reminders/update`. Requests send `x-api-key` and the `culture-invariant` header so numbers and dates are locale-independent.
