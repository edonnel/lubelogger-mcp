# lubelogger-mcp

## About this fork

This is a fork of [drakebridgewater/lubelogger-mcp](https://github.com/drakebridgewater/lubelogger-mcp), branched from upstream commit `e182246` (2026-10-19), which was reviewed in full before forking. Upstream declares the MIT license in `package.json`; it has no LICENSE file.

Every request it sends was checked against the LubeLogger 1.7.4 source: routes, field names, JSON converters and required fields. Like upstream, it has not yet been run against a live instance.

### Changes from upstream

- **Refuses to start without a credential.** If `MCP_AUTH_TOKEN` is not set, `MCP_PATH` must contain a random segment of at least 32 characters, e.g. `/mcp/<output of: openssl rand -hex 16>`. Upstream printed a warning and served the endpoint to anyone who could reach it.
- **Keeps a custom `MCP_PATH` out of the log.** Upstream printed it in its startup line, and for clients that cannot send a bearer token (the Claude app) that path is the only credential.
- **Patched dependencies**, lockfile only: `body-parser` 2.4.0 ([GHSA-27r3-jxmh-p828](https://github.com/advisories/GHSA-27r3-jxmh-p828), denial of service) and `fast-uri` 3.1.9 ([GHSA-w74x-v6f9-j3xg](https://github.com/advisories/GHSA-w74x-v6f9-j3xg) and related).
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
| `PORT` / `HOST` | `3000` / `0.0.0.0` | |
| `CONFIRM_TTL_MINUTES` | `30` | How long a preview token stays valid |
| `REQUEST_TIMEOUT_MS` | `15000` | Timeout for LubeLogger calls |

### 3. Run with Docker next to LubeLogger

See `docker-compose.example.yml`. Either add the `lubelogger-mcp` service to your existing LubeLogger compose file (simplest, then `LUBELOGGER_URL=http://lubelogger:8080` works as-is), or attach it to LubeLogger's network.

```bash
docker compose up -d --build
curl http://localhost:3000/healthz   # {"status":"ok"}
```

Without Docker: `npm ci && npm run build && npm start` (Node 20+).

### 4. Connect Claude

**Claude Code** (works for anything on your LAN or Tailscale):

```bash
claude mcp add --transport http lubelogger http://<server>:3000/mcp \
  --header "Authorization: Bearer <MCP_AUTH_TOKEN>"
```

**Claude app / claude.ai custom connector:** as far as I know, remote connectors are called from Anthropic's cloud, not from your phone or LAN. That means the URL must be reachable over public HTTPS (reverse proxy, Cloudflare Tunnel, Tailscale Funnel). The connector UI also doesn't take a static bearer header (it supports OAuth or none). So for this route, set `MCP_PATH` to a long random path and treat that URL as a secret. Check Anthropic's current connector docs before relying on this, since it changes.

## Security notes

- This server holds an API key that can add records to your LubeLogger, so it refuses to start without either `MCP_AUTH_TOKEN` or a secret `MCP_PATH`. Keep it LAN/VPN-only where you can.
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
