# Sign-in chooser: several login methods on one server

Status: draft for review, 2026-11-05. Amends `2026-11-04-oauth-design.md` (approved), which stays the authority for everything not changed here. Mockup: the "MCP Sign-in Chooser" artifact.

## Intent

The approved OAuth design runs exactly one login method per server, chosen by `AUTH_MODE`, and lists "more than one login method at the same time" as a non-goal. The owner wants the sign-in screen to work like GitHub's and most other sites': every login method the server has switched on appears on one screen, as a button or a form, and the person picks one.

This matters most for the public fork. A household can offer Home Assistant to the admin and a LubeLogger password to everyone else, or move from one method to another without cutting everyone off at once.

## Goals

- Any combination of the four login methods (Home Assistant, OpenID Connect, LubeLogger password, LubeLogger API key) can be on at once.
- One sign-in screen at `/authorize` shows every method that is on, and replaces today's separate approval page.
- **Methods are switched on in configuration, as today** (the owner's decision, option A in the mockup). Locally that means environment variables. In the add-on, each method gets a checkbox plus its own settings.
- Existing deployments keep working unchanged on upgrade, the reference add-on included.

## Non-goals

- A settings page served by this server, or a first-run setup screen (options B and C in the mockup). The owner chose A. A could later be extended to B, since B needs the same sign-in screen and the same method list.
- More than one OpenID Connect provider at a time.
- Bundled third-party logos.

## Anti-goals (a failure even if it "works")

- Every anti-goal of the approved design still applies.
- A way to sign in with a method that is switched off. That includes a crafted POST naming a disabled method, and a refresh of a connection whose method was switched off.
- Leaving an add-on stopped after an upgrade because a new option is required. 0.4 did this, and the Supervisor's error message printed the API key.
- The screen needing JavaScript, or loosening its Content-Security-Policy.

## Decided

### Configuration

- **`AUTH_METHODS`**: a comma-separated list of `homeassistant`, `oidc`, `lubelogger-password` and `lubelogger-key`. If it is set, OAuth is on with those methods. An unknown name, a duplicate, or an empty list refuses to start.
- **`AUTH_MODE` stays for compatibility** (my call). `token` (the default) keeps token mode. `AUTH_MODE=homeassistant` (or any single method) behaves exactly like `AUTH_METHODS=<that method>`. Setting `AUTH_METHODS` together with a non-`token` `AUTH_MODE` refuses to start, so two settings can't disagree silently.
- Each method's own settings keep the names in the approved design, and are required only when that method is on. `OIDC_DISPLAY_NAME` is new: the provider's name on its button, e.g. "Authentik", defaulting to "single sign-on".
- **The shared LubeLogger key** (`LUBELOGGER_API_KEY`) is required when any method other than `lubelogger-key` is on. Connections made with the API key method keep using the person's own key; all others use the shared key.
- The token-mode conflict rule carries over: with any OAuth method on, `MCP_AUTH_TOKEN` or a custom `MCP_PATH` refuses to start.

### The sign-in screen

- **Layout, top to bottom:**
  1. The server's name.
  2. A box that names the requesting app and the host it returns to (today's approval text).
  3. Redirect methods as buttons: "Continue with Home Assistant", then "Continue with <OIDC_DISPLAY_NAME>".
  4. An "or" divider, shown only when both a button and a form are on.
  5. The LubeLogger password form.
  6. The API key form, inside a closed `<details>` titled "Use a LubeLogger API key instead". When the password method is off, it is open and has no title.
- **Choosing is approving.** There is no separate Approve step. Each button and form posts to `/login` with the one-time `loginState` and a `method` field, plus credentials for the two LubeLogger forms. The release 1 protections apply to every method unchanged:
  - the `lm_login` browser cookie;
  - the Origin check;
  - `X-Frame-Options: DENY`;
  - the strict CSP.
- **The server checks the method on every step.** A POST naming a method that is off, or one not listed for this server, gets the generic "not allowed" page and is logged. Like today's failed Origin check, it does not use up the `loginState`.
- **When a `loginState` is locked to a method** (my call, from the builder check). It locks when a redirect method sends the browser away, or when a LubeLogger form's check succeeds. From then on it only finishes through that method. A failed password or key does not lock it, so the person can still try another method on the same screen. If the person backs out of a redirect login, they start again from Claude, as today.
- **Wrong password or key.** The screen comes back with an error above the form that failed. The username is kept, and the password and key fields are cleared. The `loginState` survives until it expires.
- **A form posted after its `loginState` expired** gets today's "Login expired, start again from Claude" page, with no retry link (my call).
- **Rate limiting** follows the approved design: per address for both LubeLogger forms, and per username for the password form. The key form has no username. Five failures in 15 minutes locks that address or username for 15 minutes (my call). During a lockout the screen says when to try again. A lockout reads the same whether or not the username exists, so it doesn't reveal which accounts are real.
- If a redirect method's upstream is down, its button still shows. Pressing it gives the existing "try again shortly" page.

### Connections

- **Each connection records the method that created it** (my call). Refreshes and cleanup go through that method.
- **Switching a method off ends its connections** at their next refresh, as a definite refusal (my call). This matches "access can be withdrawn at the source within the hour". The startup purge also removes them.
- **Upstream cleanup after a method is switched off is best effort** (my call, from the builder check). If that method's settings are still present, its upstream session is revoked as usual. If they are not, the connection is still removed, and the log says its upstream session could not be revoked.
  - In the add-on this rarely comes up: unticking a method's checkbox keeps its saved settings, and `HOME_ASSISTANT_URL` is always set by the launcher.
  - The README tells others to switch a method off before deleting its settings.
- **Identities belong to their method** (my call). Connections, replacement and the scoping of pending confirmations are keyed by method plus person, so a Home Assistant user ID can never match a LubeLogger username. Nobody is treated as the same person across methods. A person who signs in to the same Claude client through two methods gets two connections. A new sign-in replaces the earlier connection for the same client, method and person, as today.
- **The LubeLogger key is chosen per connection** (my call). The verified request carries which key to use: the person's own key for the API key method, and the shared key for the others. The LubeLogger client is built per request from it.
  - Step 1 sets up that shape, with the shared key throughout.
  - Step 3 adds the person's own key.
- Connections stored by release 1 have no method recorded. They are read as `homeassistant`, the only method release 1 could create, so nobody has to reconnect after the upgrade.

### The reference add-on

- It gets a boolean option per method: `homeassistant` (default on) and `oidc`, `lubelogger_password`, `lubelogger_key` (default off). Each method's settings are optional in the schema (`str?` / `url?` / `password?`). `public_url` and `home_assistant_public_url` become optional too.
- **An option ships with its method** (my call). Step 1 adds only the `homeassistant` checkbox. The OIDC options arrive with step 2, and the LubeLogger ones with step 3, so the form never offers a method that can't work yet.
- **A missing `homeassistant` option counts as on** (my call). Installs upgraded from 0.4 have no saved value for it, and only an explicit `false` switches it off. Otherwise an upgrade would leave the add-on with no method and stopped.
- **`launch.mjs` validates instead of the Supervisor.** If a switched-on method is missing a setting, it exits with a clear message that names the setting and never prints option values. An upgrade then never fails in the Supervisor, so its error message never repeats the API key.
- `launch.mjs` builds `AUTH_METHODS` from the booleans. It never sets `AUTH_MODE`.

## Delivery (my call)

This replaces the approved design's three releases. Each step can be tested and deployed on its own:

1. **Method list and sign-in screen.** Add `AUTH_METHODS`, the screen, method recording on connections, and the add-on's checkbox options. Home Assistant is the only method at first.
2. **OpenID Connect**, as designed, with its named button.
3. **The two LubeLogger methods**, as designed, with their forms and rate limiting.

## Left to the builder

- Exact wording on the screen and its error states, in plain language (the mockup is the reference).
- The screen's styling. It must not depend on scripts or external assets, and must read well in both light and dark (`prefers-color-scheme`).
- How the rate limiter stores its counts. Keeping them in memory is acceptable, since a restart only resets lockouts.
- How the method appears on a stored connection, and the read-as-`homeassistant` default for release 1 connections.
- Tests:
  - the screen for each combination of methods that are on;
  - a POST naming a disabled or unknown method;
  - reusing one `loginState` with a second method;
  - switching a method off ending its connections;
  - a release 1 data file loading unchanged;
  - `launch.mjs` failing clearly, without printing values, for each missing setting.

## Carried into step 2 (from step 1's final review)

- **Done. Revoke a switched-off method's upstream sessions when its settings are still present.** Step 1 only revokes through methods that are on. With a single method there was nothing to reach, since removing it returns the server to token mode. Step 2 adds a second method, so it has to build the switched-off method from its remaining settings for cleanup, as "Connections" above describes. Covered by `a switched-off method that is still configured has its upstream session revoked` in `test/oauth-ha.mjs`.
- **Done. Test that a `loginState` locked to one method refuses a second method.** This is listed under "Left to the builder". It could only be written once there were two real methods. Covered by `a login state locked to one method refuses a second` in `test/oauth-ha.mjs`.

## Follow-ups after step 2 (from its reviews; none lets the wrong person in)

- The startup purge waits on a retired method's cleanup, so a provider that drops packets can delay startup by up to 10 s per leftover connection, once. End switched-off connections without awaiting their cleanup.
- When a refresh succeeds but the new ID token is refused, revoke the rotated refresh token best-effort, so the provider's session doesn't outlive the refusal.
- A refreshed ID token without a `name` claim renames the person: fall back to the stored name before `sub`.
- Refuse `OIDC_AUTH_PARAMS` that sets `client_id`, `response_type`, `response_mode`, `request` or `request_uri`.
- Remove the unused `OidcLogin` error class `OidcRejected`.
- Tests: the signature check on refresh, the timeout path, cleanup throwing, the real retired-method build, markup in `OIDC_DISPLAY_NAME`, per-check baselines for `stubOidc.started`, and a test helper that names which bad-token case failed.
- Launcher: treat whitespace-only options as unset; test that `oidc` alone doesn't require `home_assistant_public_url`.
- `.env.example`: one comment per allowlist setting, and the "Home Assistant mode" wording on `DATA_DIR` and `ALLOWED_REDIRECT_HOSTS`.
