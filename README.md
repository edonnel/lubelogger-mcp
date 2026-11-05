# lubelogger-mcp

## About this fork

This is a fork of [drakebridgewater/lubelogger-mcp](https://github.com/drakebridgewater/lubelogger-mcp), branched from upstream commit `e182246` (2026-10-19), which was reviewed in full before forking. Upstream declares the MIT license in `package.json`; it has no LICENSE file.

Every request it sends was checked against the LubeLogger 1.7.4 source: routes, field names, JSON converters and required fields. Like upstream, it has not yet been run against a live instance.

### Changes from upstream

- **Refuses to start without a credential.** If `MCP_AUTH_TOKEN` is not set, `MCP_PATH` must contain a random segment of at least 32 characters, e.g. `/mcp/<output of: openssl rand -hex 16>`. Upstream printed a warning and served the endpoint to anyone who could reach it.
- **Keeps a custom `MCP_PATH` out of the log.** Upstream printed it in its startup line, and for clients that cannot send a bearer token (the Claude app) that path is the only credential.
- **Patched dependencies**, lockfile only: `body-parser` 2.4.0 ([GHSA-27r3-jxmh-p828](https://github.com/advisories/GHSA-27r3-jxmh-p828), denial of service) and `fast-uri` 3.1.9 ([GHSA-w74x-v6f9-j3xg](https://github.com/advisories/GHSA-w74x-v6f9-j3xg) and related).
- **Sign in with Home Assistant (OAuth).** With `AUTH_METHODS=homeassistant`, the Claude app connects through a plain `https://<host>/mcp` URL and a Home Assistant login instead of a secret path. `AUTH_METHODS` is a list of sign-in methods, so more can be added later; `AUTH_MODE=homeassistant` still works and means the same thing. Only Home Assistant admins (`is_admin`) can connect. See [Sign in with Home Assistant](#sign-in-with-home-assistant-oauth). With neither set, `AUTH_MODE` defaults to `token`, the behaviour above.
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
| `LUBELOGGER_API_KEY` | required | Sent as the `x-api-key` header |
| `MCP_AUTH_TOKEN` | unset | If set, every MCP request needs `Authorization: Bearer <token>`. If unset, `MCP_PATH` must hold a secret segment or the server will not start |
| `MCP_PATH` | `/mcp` | Without `MCP_AUTH_TOKEN`, must contain a random segment of at least 32 characters, e.g. `/mcp/<output of: openssl rand -hex 16>`. A custom path is never printed in the log |
| `AUTH_METHODS` | unset | Comma-separated sign-in methods for OAuth: `homeassistant`, `oidc`, `lubelogger-password` and `lubelogger-key`. Only `homeassistant` is available in this version; the others refuse to start with "is not available in this version". Never set it together with a non-token `AUTH_MODE` |
| `AUTH_MODE` | `token` | `token` is the bearer token or secret path above. `homeassistant` still works and means `AUTH_METHODS=homeassistant`. Setting `AUTH_METHODS` together with a non-token `AUTH_MODE` refuses to start |
| `PUBLIC_URL` | unset | Home Assistant mode only, required. This server's public address, origin only with no path, e.g. `https://mcp.example.com` |
| `HOME_ASSISTANT_PUBLIC_URL` | unset | Home Assistant mode only, required. Home Assistant's address as your browser sees it, no path, e.g. `https://ha.example.com` |
| `HOME_ASSISTANT_URL` | unset | Home Assistant mode only, required. Home Assistant's address as this server reaches it, no path, e.g. `http://homeassistant:8123` inside the add-on network |
| `DATA_DIR` | `./data` | Home Assistant mode. Holds `oauth.json` with the registered clients and connections. Keep it private and back it up |
| `ALLOWED_REDIRECT_HOSTS` | `claude.ai,claude.com` | Home Assistant mode. Hosts a login code may be sent back to, comma-separated bare hostnames with no scheme or port. Only these hosts can register as clients. Add `localhost,127.0.0.1` for Claude Code |
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

**Switching a method off.** Taking a method out of `AUTH_METHODS` (or unchecking it in the add-on) ends its connections at their next refresh. If you also delete that method's settings, this server can no longer reach the upstream session to revoke it, so switch the method off first and delete its settings afterwards.

The startup log says which methods are on: `auth homeassistant`, or `auth token` in token mode.

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

## Lock it down with Cloudflare

If the server is public through Cloudflare, you can have Cloudflare refuse requests that do not come from Anthropic's cloud, apart from the browser sign-in paths. It is optional once OAuth is on, because the sign-in already protects `/mcp`. In token mode with a secret path it is the main extra protection, since the path is the only credential. It rules out Claude Code, which calls from your own machine.

In the Cloudflare dashboard, open the zone, then **Security → WAF → Custom rules**, and create a rule with action **Block** and this expression (replace `mcp.example.com` with your host):

```
(http.host eq "mcp.example.com" and not ip.src in {160.79.104.0/21 153.61.208.0/20} and not http.request.uri.path in {"/authorize" "/login" "/login/callback"})
```

- The two ranges are Anthropic's published addresses, listed on [Anthropic's IP addresses page](https://docs.anthropic.com/en/api/ip-addresses). They can change, so check that page again if Claude stops reaching the server.
- The OAuth endpoints that Claude's servers call (`/.well-known/…`, `/register`, `/token`, `/revoke`) come from Anthropic's addresses, so the IP clause already lets them through.
- The path clause leaves the browser sign-in paths open, because you reach them from your own browser. In token mode there is no sign-in, so drop the last clause: `(http.host eq "mcp.example.com" and not ip.src in {160.79.104.0/21 153.61.208.0/20})`.
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
