// The OAuth authorization server toward Claude. The SDK's router handles the protocol (discovery, registration,
// PKCE, the token and revoke endpoints); this provider issues and checks tokens, and delegates "who are you"
// to a LoginMethod. No token, code or login state is ever written to a log: only people's names.
import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import type express from "express";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import {
  InvalidClientMetadataError,
  InvalidGrantError,
  InvalidTokenError,
  TemporarilyUnavailableError,
} from "@modelcontextprotocol/sdk/server/auth/errors.js";
import type { AuthorizationParams, OAuthServerProvider } from "@modelcontextprotocol/sdk/server/auth/provider.js";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import type {
  OAuthClientInformationFull,
  OAuthTokenRevocationRequest,
  OAuthTokens,
} from "@modelcontextprotocol/sdk/shared/auth.js";
import type { MethodName } from "../config.js";
import {
  isFormMethod,
  type AnyLoginMethod,
  type FormCheckResult,
  type FormFields,
  type FormLoginMethod,
  type LoginMethod,
  type RecheckResult,
} from "./login-method.js";
import { addressKey, FailureLimiter, MAX_FAILURES, MAX_KEY_LENGTH } from "./rate-limit.js";
import {
  BUTTON_LABEL,
  escapeHtml,
  PAGE_HEADERS,
  pageShell,
  signInPage,
  type FormKind,
  type MethodChoice,
} from "./signin-page.js";
import { hashToken, REFRESH_GRACE_MS, type AuthStore, type Connection, type Person } from "./store.js";

export const ACCESS_TOKEN_TTL_MS = 60 * 60_000;
export const LOGIN_STATE_TTL_MS = 10 * 60_000;
export const CODE_TTL_MS = 10 * 60_000;
/** How often connections unused for 90 days are looked for and removed. */
export const PURGE_INTERVAL_MS = 60 * 60_000;

/** Binds a login to the browser that saw the sign-in screen. Path=/login covers /login and /login/callback. */
const LOGIN_COOKIE = "lm_login";
const COOKIE_ATTRIBUTES = "HttpOnly; Secure; SameSite=Lax; Path=/login";

const EXPIRED_LINK = "This login link has expired, start again from Claude.";

const EXPIRED_UNUSED = "expired after 90 days unused";

const METHOD_OFF = "sign-in method switched off";

/** Shown when a form post is refused only because enough attempts on its keys are still being checked. */
export const STILL_CHECKING = "A sign-in is still being checked. Try again in a moment.";

/** The longest username, password or key read from a sign-in form; anything longer is cut, never sent whole. */
const MAX_FIELD_LENGTH = 512;

/** The method whose connections act with the person's own LubeLogger API key. */
const KEY_METHOD: MethodName = "lubelogger-key";

export const DEFAULT_REDIRECT_HOSTS = ["claude.ai", "claude.com"];

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1"]);

// method: the one the person chose on the sign-in screen. Only then is a login method's answer accepted, and only
// that method's. browserHash: the SHA-256 of the nonce in the sign-in screen's cookie, which choosing and callback
// must present. appName and returnHost: what the screen named, kept so it can be shown again after a failed form.
type LoginState = {
  clientId: string;
  params: AuthorizationParams;
  createdAt: number;
  method?: MethodName;
  browserHash: string;
  appName: string;
  returnHost: string;
};

type PendingCode = {
  clientId: string;
  params: AuthorizationParams;
  method: MethodName;
  person: Person;
  upstream: Record<string, unknown>;
  createdAt: number;
};

// lubeloggerKey: the person's own LubeLogger API key, for lubelogger-key connections only
type AccessGrant = {
  connectionId: string;
  clientId: string;
  method: MethodName;
  person: Person;
  expiresAt: number;
  lubeloggerKey?: string;
};

// the pair a rotation issued, kept so a retry with the previous refresh token gets the same answer
type RecentRotation = { refreshHash: string; tokens: OAuthTokens; rotatedAt: number };

const newSecret = () => randomBytes(32).toString("base64url");

function log(message: string): void {
  console.error(`[auth] ${message}`);
}

/** A person's name for a log line, quoted and escaped so a name cannot forge or break a line. */
function who(person: Person | undefined): string {
  return JSON.stringify(person?.name ?? "unknown");
}

/** Sends a small page. `body` is trusted HTML: escape anything interpolated into it. */
function sendPage(res: express.Response, status: number, title: string, body: string): void {
  res
    .status(status)
    .set(PAGE_HEADERS)
    .type("html")
    .send(pageShell(title, body));
}

export function page(res: express.Response, status: number, title: string, message: string): void {
  sendPage(res, status, title, `<div class="box"><p>${escapeHtml(message)}</p></div>`);
}

/** The hostname of an allowed redirect URI, or undefined: https to a listed host, or http to a listed loopback host. */
function allowedRedirectHost(uri: string, allowed: readonly string[]): string | undefined {
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return undefined;
  }
  const host = url.hostname.toLowerCase();
  if (!allowed.includes(host)) return undefined;
  if (url.protocol === "https:") return host;
  if (url.protocol === "http:" && LOOPBACK_HOSTS.has(host)) return host;
  return undefined;
}

/** The login cookie's value from a Cookie header, or "". */
function loginCookie(req: express.Request): string {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0 && part.slice(0, eq).trim() === LOGIN_COOKIE) return part.slice(eq + 1).trim();
  }
  return "";
}

/** True when the request carries the cookie whose nonce hashes to `browserHash`. */
function sameBrowser(req: express.Request, browserHash: string): boolean {
  const nonce = loginCookie(req);
  if (!nonce) return false;
  const a = Buffer.from(hashToken(nonce), "hex");
  const b = Buffer.from(browserHash, "hex");
  return a.length === b.length && timingSafeEqual(a, b);
}

function clearLoginCookie(res: express.Response): void {
  res.append("Set-Cookie", `${LOGIN_COOKIE}=; ${COOKIE_ATTRIBUTES}; Max-Age=0`);
}

export class LoginProvider implements OAuthServerProvider {
  private readonly states = new Map<string, LoginState>();
  // codes, access tokens and recent rotations are keyed by the SHA-256 of the secret, never the secret itself
  private readonly codes = new Map<string, PendingCode>();
  private readonly access = new Map<string, AccessGrant>();
  private readonly recent = new Map<string, RecentRotation>();
  // refreshes in progress, by refresh token hash: a duplicate request waits for the first one's answer
  private readonly refreshing = new Map<string, Promise<OAuthTokens>>();

  readonly clientsStore: OAuthRegisteredClientsStore;

  private readonly allowedRedirectHosts: readonly string[];

  // the origin a browser posting the sign-in form reports, when it reports one
  private readonly publicOrigin: string | undefined;

  // button text that replaces a method's fallback label, such as the OIDC provider's name
  private readonly labels: Partial<Record<MethodName, string>>;

  // switched off but still configured: used only to revoke old connections' upstream sessions
  private readonly retired: ReadonlyMap<MethodName, AnyLoginMethod>;

  // failed form sign-ins, by address and by username
  private readonly limiter: FailureLimiter;

  // form sign-ins being checked right now, by limiter key; a key is removed when its count drops to 0
  private readonly inFlight = new Map<string, number>();

  private lastPurge: number;

  private purging: Promise<void> | undefined;

  private purgeTimer: NodeJS.Timeout | undefined;

  constructor(
    private readonly store: AuthStore,
    private readonly methods: ReadonlyMap<MethodName, AnyLoginMethod>,
    private readonly now: () => number = Date.now,
    opts: {
      allowedRedirectHosts?: readonly string[];
      publicUrl?: string;
      labels?: Partial<Record<MethodName, string>>;
      retired?: ReadonlyMap<MethodName, AnyLoginMethod>;
      limiter?: FailureLimiter;
    } = {},
  ) {
    if (methods.size === 0) throw new Error("at least one sign-in method is required");
    this.allowedRedirectHosts = opts.allowedRedirectHosts ?? DEFAULT_REDIRECT_HOSTS;
    this.labels = opts.labels ?? {};
    this.retired = opts.retired ?? new Map();
    this.limiter = opts.limiter ?? new FailureLimiter(now);
    this.publicOrigin = opts.publicUrl ? new URL(opts.publicUrl).origin : undefined;
    this.lastPurge = this.now();
    this.clientsStore = {
      getClient: (id) => store.getClient(id),
      registerClient: async (client) => {
        // only Claude's own return addresses: otherwise anyone could register a client that sends codes to their server
        for (const uri of client.redirect_uris)
          if (!allowedRedirectHost(uri, this.allowedRedirectHosts))
            throw new InvalidClientMetadataError("redirect_uris may only point to an allowed host over https");
        // the SDK's registration handler always generates client_id before calling this
        const full = client as OAuthClientInformationFull;
        await store.saveClient(full);
        log(`registered client ${JSON.stringify(full.client_name ?? "(unnamed)")}`);
        return full;
      },
    };
  }

  async authorize(client: OAuthClientInformationFull, params: AuthorizationParams, res: express.Response): Promise<void> {
    this.sweep();
    // checked again in case a client was registered before the allowlist changed; never send the browser to it
    const host = allowedRedirectHost(params.redirectUri, this.allowedRedirectHosts);
    if (!host) {
      page(res, 400, "Not allowed", "This app's return address is not allowed on this server.");
      return;
    }

    const loginState = newSecret();
    const nonce = newSecret();
    const entry: LoginState = {
      clientId: client.client_id,
      params,
      createdAt: this.now(),
      browserHash: hashToken(nonce),
      appName: client.client_name?.trim() ? client.client_name.trim() : "An unnamed app",
      returnHost: host,
    };
    this.states.set(loginState, entry);
    res.append(
      "Set-Cookie",
      `${LOGIN_COOKIE}=${nonce}; ${COOKIE_ATTRIBUTES}; Max-Age=${Math.floor(LOGIN_STATE_TTL_MS / 1000)}`,
    );
    this.showScreen(res, 200, loginState, entry);
  }

  /** The sign-in screen for `entry`, or the same screen again after a failed form, with its error and username. */
  private showScreen(
    res: express.Response,
    status: number,
    loginState: string,
    entry: LoginState,
    failed?: { form: FormKind; message: string; username?: string },
  ): void {
    // a button per redirect method and a form per form method, in the order the methods were configured
    const choices: MethodChoice[] = [];
    const forms: { password?: boolean; key?: boolean } = {};
    for (const [method, login] of this.methods) {
      if (isFormMethod(login)) forms[login.form] = true;
      else choices.push({ method, label: this.labels[method] ?? BUTTON_LABEL[method] });
    }
    const error = failed ? { form: failed.form, message: failed.message } : undefined;
    res
      .status(status)
      .set(PAGE_HEADERS)
      .type("html")
      .send(
        signInPage({
          appName: entry.appName,
          returnHost: entry.returnHost,
          loginState,
          choices,
          forms,
          error,
          username: failed?.username,
        }),
      );
  }

  /** POST /login: the person pressed a method's button, or sent a form, on the screen `authorize` showed. Never throws. */
  async handleChoose(req: express.Request, res: express.Response): Promise<void> {
    try {
      this.sweep();
      const body = (req.body ?? {}) as Record<string, unknown>;
      const loginState = typeof body.loginState === "string" ? body.loginState : "";
      const entry = this.states.get(loginState);
      // choosing is single use: once a method is chosen the state only finishes through it, so a second press
      // (Back, then press again) has to start again. That state is kept, so the login under way still finishes
      const expired = entry !== undefined && this.now() - entry.createdAt > LOGIN_STATE_TTL_MS;
      if (!entry || expired || entry.method !== undefined) {
        if (expired) this.states.delete(loginState);
        page(res, 400, "Login expired", EXPIRED_LINK);
        return;
      }
      // only the browser that was shown the sign-in screen may choose: a form posted from another
      // site carries a foreign Origin, or no login cookie. The state is kept, so the real page still works
      const origin = req.headers.origin;
      if ((origin !== undefined && origin !== this.publicOrigin) || !sameBrowser(req, entry.browserHash)) {
        page(res, 400, "Login expired", EXPIRED_LINK);
        return;
      }
      // a method that is off, or no method at all (a release 1 page still open in a tab); the state is kept
      const value = body.method;
      const method = typeof value === "string" ? this.methods.get(value as MethodName) : undefined;
      if (!method) {
        log(`sign-in with unavailable method ${JSON.stringify(String(value ?? "").slice(0, 40))} refused`);
        page(res, 400, "Not available", "That sign-in method is not available on this server.");
        return;
      }
      if (isFormMethod(method)) {
        await this.checkForm(req, res, loginState, entry, value as MethodName, method);
        return;
      }
      entry.method = value as MethodName;
      await method.start(loginState, res);
    } catch (err) {
      log(`login could not be started: ${err instanceof Error ? err.message : "unknown error"}`);
      if (!res.headersSent) page(res, 502, "Login failed", "The login could not be started. Start again from Claude.");
    }
  }

  /** GET /login/callback: the browser comes back from the login method. Never throws. */
  async handleCallback(req: express.Request, res: express.Response): Promise<void> {
    try {
      this.sweep();
      const loginState = typeof req.query.state === "string" ? req.query.state : "";
      const entry = this.states.get(loginState);
      // single use: gone before the login method is even asked, and the browser's cookie with it
      if (entry) this.states.delete(loginState);
      clearLoginCookie(res);
      // only through the method chosen on the sign-in screen
      const chosen = entry?.method !== undefined ? this.methods.get(entry.method) : undefined;
      const method = chosen && !isFormMethod(chosen) ? chosen : undefined;
      if (
        !entry ||
        entry.method === undefined ||
        !method ||
        this.now() - entry.createdAt > LOGIN_STATE_TTL_MS ||
        !sameBrowser(req, entry.browserHash)
      ) {
        page(res, 400, "Login expired", EXPIRED_LINK);
        return;
      }

      let result: Awaited<ReturnType<LoginMethod["finish"]>>;
      try {
        result = await method.finish(req);
      } catch (err) {
        log(`login could not be completed: ${err instanceof Error ? err.message : "unknown error"}`);
        page(res, 502, "Login failed", "The login could not be completed. Start again from Claude.");
        return;
      }

      if ("refused" in result) {
        log(`login refused for ${who(result.person)}: ${JSON.stringify(result.refused)}`);
        page(res, 403, "Not allowed", result.refused);
        return;
      }

      this.completeLogin(res, entry, entry.method, result.person, result.upstream);
    } catch (err) {
      log(`login callback failed: ${err instanceof Error ? err.message : "unknown error"}`);
      if (!res.headersSent) page(res, 500, "Login failed", "Something went wrong. Start again from Claude.");
    }
  }

  /**
   * A LubeLogger form sent from the sign-in screen; the state, Origin, cookie and method checks have already passed.
   * A wrong password or key, a lockout, or LubeLogger being unreachable shows the screen again and leaves the state
   * unlocked, so the person can retry or choose another method. Success, or a refusal, uses the state up.
   */
  private async checkForm(
    req: express.Request,
    res: express.Response,
    loginState: string,
    entry: LoginState,
    name: MethodName,
    method: FormLoginMethod,
  ): Promise<void> {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const field = (key: string) => {
      const value = body[key];
      return typeof value === "string" ? value.slice(0, MAX_FIELD_LENGTH) : "";
    };
    // each form fills only its own fields; the username is the only one ever shown again
    const username = method.form === "password" ? field("username") : undefined;
    const fields: FormFields =
      method.form === "password" ? { username, password: field("password") } : { apiKey: field("apiKey") };
    const showAgain = (status: number, message: string) =>
      this.showScreen(res, status, loginState, entry, { form: method.form, message, username });

    // the address always, and the username for the password form: either one being locked refuses the attempt
    // cut as the limiter cuts them, so the in-flight count and the limiter agree on what a key is
    // an IPv6 address counts by its /64, and the username ignores case and surrounding spaces (for the key only)
    const keys = [addressKey(req.ip)];
    const userKey = username?.trim().toLowerCase();
    if (userKey) keys.push(`user:${userKey}`);
    for (const [i, key] of keys.entries()) keys[i] = key.slice(0, MAX_KEY_LENGTH);
    const wait = this.limiter.lockedFor(keys);
    // attempts still being checked count too: otherwise a burst of posts all pass before any failure is recorded
    const busy = keys.some((key) => (this.inFlight.get(key) ?? 0) + this.limiter.failureCount(key) >= MAX_FAILURES);
    if (wait > 0 || busy) {
      // nothing is sent to LubeLogger, and this refusal is not itself counted as a failure
      log("sign-in refused: too many failed attempts");
      // a lock names the minutes until the key is free; attempts still in flight may yet succeed, so no wait is known
      if (wait > 0) showAgain(429, `Too many attempts. Try again in ${Math.ceil(wait / 60_000)} minutes.`);
      else showAgain(429, STILL_CHECKING);
      return;
    }

    let result: FormCheckResult;
    for (const key of keys) this.inFlight.set(key, (this.inFlight.get(key) ?? 0) + 1);
    try {
      result = await method.check(fields);
    } catch {
      // the error is left out of the log: it could carry what was typed
      log("sign-in check failed");
      showAgain(503, "The sign-in could not be checked. Try again shortly.");
      return;
    } finally {
      // runs before the failure below is recorded, with no await between, so no attempt is counted twice or not at all
      for (const key of keys) {
        const left = (this.inFlight.get(key) ?? 1) - 1;
        if (left > 0) this.inFlight.set(key, left);
        else this.inFlight.delete(key);
      }
    }

    if ("invalid" in result) {
      this.limiter.fail(keys);
      log(username === undefined ? "sign-in failed with an API key" : `sign-in failed for ${JSON.stringify(username.slice(0, 60))}`);
      showAgain(400, result.invalid);
      return;
    }
    if ("unavailable" in result) {
      log("sign-in check could not reach LubeLogger");
      showAgain(503, result.unavailable);
      return;
    }

    // another method, or another post of this form, may have used the state while LubeLogger was asked
    if (this.states.get(loginState) !== entry || entry.method !== undefined) {
      if ("upstream" in result) await this.safeCleanup(result.upstream, result.person, name);
      page(res, 400, "Login expired", EXPIRED_LINK);
      return;
    }
    this.states.delete(loginState);
    clearLoginCookie(res);

    if ("refused" in result) {
      // the message can hold a username LubeLogger supplied: shown escaped, and never logged as it is
      log(`sign-in refused for ${JSON.stringify((result.person?.name ?? username ?? "unknown").slice(0, 60))}`);
      page(res, 403, "Not allowed", result.refused);
      return;
    }
    entry.method = name;
    this.completeLogin(res, entry, name, result.person, result.upstream);
  }

  /**
   * The end of every successful login, once its state and cookie are gone: stores a one-time code for `person` and
   * sends the browser back to Claude with it.
   */
  private completeLogin(
    res: express.Response,
    entry: LoginState,
    method: MethodName,
    person: Person,
    upstream: Record<string, unknown>,
  ): void {
    const code = newSecret();
    this.codes.set(hashToken(code), {
      clientId: entry.clientId,
      params: entry.params,
      method,
      person,
      upstream,
      createdAt: this.now(),
    });
    log(`login by ${who(person)}`);

    const target = new URL(entry.params.redirectUri);
    target.searchParams.set("code", code);
    if (entry.params.state !== undefined) target.searchParams.set("state", entry.params.state);
    res.set("Cache-Control", "no-store").redirect(302, target.href);
  }

  async challengeForAuthorizationCode(client: OAuthClientInformationFull, authorizationCode: string): Promise<string> {
    return this.liveCode(client, authorizationCode).params.codeChallenge;
  }

  async exchangeAuthorizationCode(
    client: OAuthClientInformationFull,
    authorizationCode: string,
    _codeVerifier?: string,
    redirectUri?: string,
  ): Promise<OAuthTokens> {
    const entry = this.liveCode(client, authorizationCode);
    // single use: the code is spent even if the rest of the exchange fails
    this.codes.delete(hashToken(authorizationCode));

    if (redirectUri !== undefined && redirectUri !== entry.params.redirectUri) {
      await this.safeCleanup(entry.upstream, entry.person, entry.method);
      throw new InvalidGrantError("redirect_uri does not match the authorization request");
    }

    const refreshToken = newSecret();
    const connection: Connection = {
      id: randomUUID(),
      method: entry.method,
      clientId: client.client_id,
      person: entry.person,
      upstream: entry.upstream,
      refreshHash: hashToken(refreshToken),
      lastUsedAt: this.now(),
    };

    const replaced = await this.store.putConnection(connection);
    if (replaced) {
      this.forget(replaced.id);
      await this.safeCleanup(replaced.upstream, replaced.person, replaced.method);
      log(`connection for ${who(replaced.person)} replaced by a new login`);
    }

    log(`connected ${who(entry.person)}`);
    return this.issue(connection, refreshToken);
  }

  async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string): Promise<OAuthTokens> {
    // bound to the client: another client presenting the same token must not join this refresh
    const key = `${client.client_id}:${hashToken(refreshToken)}`;
    const inFlight = this.refreshing.get(key);
    if (inFlight) return inFlight;

    const run = this.refresh(client, refreshToken).finally(() => this.refreshing.delete(key));
    this.refreshing.set(key, run);
    return run;
  }

  private async refresh(client: OAuthClientInformationFull, refreshToken: string): Promise<OAuthTokens> {
    const found = this.store.findByRefresh(client.client_id, refreshToken);
    if (!found) throw new InvalidGrantError("Invalid refresh token");
    const { connection, stale } = found;

    if (this.store.expired(connection)) {
      await this.end(connection, EXPIRED_UNUSED);
      throw new InvalidGrantError("Refresh token expired");
    }

    // a method switched off is a definite refusal: the connection ends, and Claude asks the person to sign in again
    const method = this.methods.get(connection.method);
    if (!method) {
      await this.end(connection, METHOD_OFF);
      throw new InvalidGrantError("Access was withdrawn");
    }

    if (stale) {
      // a retry of a refresh that already rotated: hand back the very same pair
      const recent = this.recent.get(connection.id);
      if (recent && recent.refreshHash === connection.refreshHash && this.now() - recent.rotatedAt <= REFRESH_GRACE_MS)
        return recent.tokens;
      throw new InvalidGrantError("Refresh token was already used");
    }

    let check: RecheckResult;
    try {
      check = await method.recheck(connection.upstream);
    } catch (err) {
      check = { ok: false, reason: "unavailable" };
      log(`re-check for ${who(connection.person)} failed: ${err instanceof Error ? err.message : "unknown error"}`);
    }

    if (!check.ok && check.reason === "unavailable") {
      log(`login method unavailable while refreshing ${who(connection.person)}; refresh token kept`);
      throw new TemporarilyUnavailableError("The login service is unavailable, try again shortly");
    }

    if (!check.ok || check.person.id !== connection.person.id) {
      await this.end(connection, "refused on re-check");
      throw new InvalidGrantError("Access was withdrawn");
    }

    // the connection may have been replaced or revoked while the re-check ran
    const current = this.store.findByRefresh(client.client_id, refreshToken);
    if (!current || current.stale || current.connection.id !== connection.id)
      throw new InvalidGrantError("Invalid refresh token");

    const next = newSecret();
    const rotatedAt = this.now();
    const updated: Connection = {
      ...current.connection,
      person: check.person,
      upstream: check.upstream,
      refreshHash: hashToken(next),
      previousRefreshHash: current.connection.refreshHash,
      rotatedAt,
      lastUsedAt: rotatedAt,
    };
    await this.store.updateConnection(updated);

    const tokens = this.issue(updated, next);
    this.recent.set(updated.id, { refreshHash: updated.refreshHash, tokens, rotatedAt });
    return tokens;
  }

  async verifyAccessToken(token: string): Promise<AuthInfo> {
    const key = hashToken(token);
    const grant = this.access.get(key);
    if (!grant || grant.expiresAt <= this.now()) {
      if (grant) this.access.delete(key);
      throw new InvalidTokenError("Invalid or expired access token");
    }
    return {
      token,
      clientId: grant.clientId,
      scopes: [],
      expiresAt: Math.floor(grant.expiresAt / 1000),
      extra: {
        method: grant.method,
        personId: grant.person.id,
        personName: grant.person.name,
        ...(grant.lubeloggerKey !== undefined ? { lubeloggerKey: grant.lubeloggerKey } : {}),
      },
    };
  }

  async revokeToken(client: OAuthClientInformationFull, request: OAuthTokenRevocationRequest): Promise<void> {
    const key = hashToken(request.token);
    const grant = this.access.get(key);
    if (grant) {
      if (grant.clientId === client.client_id) this.access.delete(key);
      return;
    }

    const found = this.store.findByRefresh(client.client_id, request.token);
    if (found) await this.end(found.connection, "revoked");
  }

  /**
   * Removes every connection unused for 90 days, or made by a method that is now switched off, and ends its
   * upstream session where it can. A connection Claude abandoned
   * (say, after the connector was added again under a new client) is never presented again, so checking
   * on refresh alone would keep its upstream session forever.
   */
  purgeExpired(): Promise<void> {
    this.lastPurge = this.now();
    // one run at a time; .finally always runs later, so the next call starts a fresh run
    this.purging ??= this.purgeOnce().finally(() => {
      this.purging = undefined;
    });
    return this.purging;
  }

  private async purgeOnce(): Promise<void> {
    try {
      for (const connection of this.store.connections()) {
        if (this.store.expired(connection)) await this.end(connection, EXPIRED_UNUSED);
        // a switched-off method's cleanup is not waited on: one that hangs must not hold up startup or the next purge
        else if (!this.methods.has(connection.method)) await this.end(connection, METHOD_OFF, { awaitCleanup: false });
      }
    } catch (err) {
      log(`purging expired connections failed: ${err instanceof Error ? err.message : "unknown error"}`);
    }
  }

  /** Purges now, then every PURGE_INTERVAL_MS until close(), so an idle server still lets go of old sessions. */
  async startPurging(): Promise<void> {
    await this.purgeExpired();
    this.purgeTimer = setInterval(() => void this.purgeExpired(), PURGE_INTERVAL_MS);
    this.purgeTimer.unref();
  }

  /** Called on shutdown: sessions behind codes that were never exchanged would otherwise be orphaned. */
  async close(): Promise<void> {
    if (this.purgeTimer) clearInterval(this.purgeTimer);
    this.purgeTimer = undefined;
    await this.purging;
    const pending = [...this.codes.values()];
    this.codes.clear();
    this.states.clear();
    await Promise.all(pending.map((c) => this.safeCleanup(c.upstream, c.person, c.method)));
  }

  private liveCode(client: OAuthClientInformationFull, code: string): PendingCode {
    this.sweep();
    const entry = this.codes.get(hashToken(code));
    if (!entry || entry.clientId !== client.client_id)
      throw new InvalidGrantError("Invalid authorization code");
    return entry;
  }

  private issue(connection: Connection, refreshToken: string): OAuthTokens {
    const accessToken = newSecret();
    // only an API-key connection has a key of its own; every other one acts with the shared key
    const apiKey = connection.upstream.apiKey;
    this.access.set(hashToken(accessToken), {
      connectionId: connection.id,
      clientId: connection.clientId,
      method: connection.method,
      person: connection.person,
      expiresAt: this.now() + ACCESS_TOKEN_TTL_MS,
      ...(connection.method === KEY_METHOD && typeof apiKey === "string" && apiKey ? { lubeloggerKey: apiKey } : {}),
    });
    return {
      access_token: accessToken,
      token_type: "bearer",
      expires_in: ACCESS_TOKEN_TTL_MS / 1000,
      refresh_token: refreshToken,
    };
  }

  /**
   * Removes a connection, its access tokens and its upstream session. Only the first of two racing calls acts.
   * With `awaitCleanup: false` the upstream cleanup is started but not waited on; safeCleanup never throws.
   */
  private async end(connection: Connection, why: string, opts: { awaitCleanup?: boolean } = {}): Promise<void> {
    const removed = await this.store.removeConnection(connection.id);
    if (!removed) return;
    this.forget(connection.id);
    const cleanup = this.safeCleanup(connection.upstream, connection.person, connection.method);
    if (opts.awaitCleanup ?? true) await cleanup;
    else void cleanup;
    log(`disconnected ${who(connection.person)} (${why})`);
  }

  private forget(connectionId: string): void {
    this.recent.delete(connectionId);
    for (const [key, grant] of this.access) if (grant.connectionId === connectionId) this.access.delete(key);
  }

  /**
   * Ends an upstream session through the method that made it, or through that method's retired copy when it is
   * switched off but still configured. Best effort when it is neither.
   */
  private async safeCleanup(upstream: Record<string, unknown>, person: Person, method: MethodName): Promise<void> {
    const login = this.methods.get(method) ?? this.retired.get(method);
    if (!login) {
      log(`upstream session for ${who(person)} could not be revoked (${METHOD_OFF})`);
      return;
    }
    try {
      await login.cleanup(upstream);
    } catch (err) {
      log(`cleanup for ${who(person)} failed: ${err instanceof Error ? err.message : "unknown error"}`);
    }
  }

  private sweep(): void {
    const t = this.now();
    for (const [key, s] of this.states) if (t - s.createdAt > LOGIN_STATE_TTL_MS) this.states.delete(key);
    for (const [key, c] of this.codes) {
      if (t - c.createdAt > CODE_TTL_MS) {
        this.codes.delete(key);
        void this.safeCleanup(c.upstream, c.person, c.method);
      }
    }
    for (const [key, g] of this.access) if (g.expiresAt <= t) this.access.delete(key);
    for (const [key, r] of this.recent) if (t - r.rotatedAt > REFRESH_GRACE_MS) this.recent.delete(key);
    if (t - this.lastPurge >= PURGE_INTERVAL_MS) void this.purgeExpired();
  }
}
