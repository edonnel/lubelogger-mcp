// The OAuth authorization server toward Claude. The SDK's router handles the protocol (discovery, registration,
// PKCE, the token and revoke endpoints); this provider issues and checks tokens, and delegates "who are you"
// to a LoginMethod. No token, code or login state is ever written to a log: only people's names.
import { randomBytes, randomUUID } from "node:crypto";
import type express from "express";
import type { OAuthRegisteredClientsStore } from "@modelcontextprotocol/sdk/server/auth/clients.js";
import {
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
import type { LoginMethod, RecheckResult } from "./login-method.js";
import { hashToken, REFRESH_GRACE_MS, type AuthStore, type Connection, type Person } from "./store.js";

export const ACCESS_TOKEN_TTL_MS = 60 * 60_000;
export const LOGIN_STATE_TTL_MS = 10 * 60_000;
export const CODE_TTL_MS = 10 * 60_000;

const EXPIRED_LINK = "This login link has expired, start again from Claude.";

type LoginState = { clientId: string; params: AuthorizationParams; createdAt: number };

type PendingCode = {
  clientId: string;
  params: AuthorizationParams;
  person: Person;
  upstream: Record<string, unknown>;
  createdAt: number;
};

type AccessGrant = { connectionId: string; clientId: string; person: Person; expiresAt: number };

// the pair a rotation issued, kept so a retry with the previous refresh token gets the same answer
type RecentRotation = { refreshHash: string; tokens: OAuthTokens; rotatedAt: number };

const newSecret = () => randomBytes(32).toString("base64url");

function log(message: string): void {
  console.error(`[auth] ${message}`);
}

const HTML_ESCAPES: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" };

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => HTML_ESCAPES[ch] ?? ch);
}

function page(res: express.Response, status: number, title: string, message: string): void {
  res
    .status(status)
    .set("Cache-Control", "no-store")
    .type("html")
    .send(
      "<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\">" +
        `<title>${escapeHtml(title)}</title></head>` +
        `<body style="font-family:system-ui,sans-serif;max-width:32rem;margin:3rem auto;padding:0 1rem">` +
        `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p></body></html>`,
    );
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

  constructor(
    private readonly store: AuthStore,
    private readonly method: LoginMethod,
    private readonly now: () => number = Date.now,
  ) {
    this.clientsStore = {
      getClient: (id) => store.getClient(id),
      registerClient: async (client) => {
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
    const loginState = newSecret();
    this.states.set(loginState, { clientId: client.client_id, params, createdAt: this.now() });
    await this.method.start(loginState, res);
  }

  /** GET /login/callback: the browser comes back from the login method. Never throws. */
  async handleCallback(req: express.Request, res: express.Response): Promise<void> {
    try {
      this.sweep();
      const loginState = typeof req.query.state === "string" ? req.query.state : "";
      const entry = this.states.get(loginState);
      // single use: gone before the login method is even asked
      if (entry) this.states.delete(loginState);
      if (!entry || this.now() - entry.createdAt > LOGIN_STATE_TTL_MS) {
        page(res, 400, "Login expired", EXPIRED_LINK);
        return;
      }

      let result: Awaited<ReturnType<LoginMethod["finish"]>>;
      try {
        result = await this.method.finish(req);
      } catch (err) {
        log(`login could not be completed: ${err instanceof Error ? err.message : "unknown error"}`);
        page(res, 502, "Login failed", "The login could not be completed. Start again from Claude.");
        return;
      }

      if ("refused" in result) {
        log(`login refused: ${result.refused}`);
        page(res, 403, "Not allowed", result.refused);
        return;
      }

      const code = newSecret();
      this.codes.set(hashToken(code), {
        clientId: entry.clientId,
        params: entry.params,
        person: result.person,
        upstream: result.upstream,
        createdAt: this.now(),
      });
      log(`login by ${result.person.name}`);

      const target = new URL(entry.params.redirectUri);
      target.searchParams.set("code", code);
      if (entry.params.state !== undefined) target.searchParams.set("state", entry.params.state);
      res.set("Cache-Control", "no-store").redirect(302, target.href);
    } catch (err) {
      log(`login callback failed: ${err instanceof Error ? err.message : "unknown error"}`);
      if (!res.headersSent) page(res, 500, "Login failed", "Something went wrong. Start again from Claude.");
    }
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
      await this.safeCleanup(entry.upstream, entry.person);
      throw new InvalidGrantError("redirect_uri does not match the authorization request");
    }

    const refreshToken = newSecret();
    const connection: Connection = {
      id: randomUUID(),
      clientId: client.client_id,
      person: entry.person,
      upstream: entry.upstream,
      refreshHash: hashToken(refreshToken),
      lastUsedAt: this.now(),
    };

    const replaced = await this.store.putConnection(connection);
    if (replaced) {
      this.forget(replaced.id);
      await this.safeCleanup(replaced.upstream, replaced.person);
      log(`connection for ${replaced.person.name} replaced by a new login`);
    }

    log(`connected ${entry.person.name}`);
    return this.issue(connection, refreshToken);
  }

  async exchangeRefreshToken(client: OAuthClientInformationFull, refreshToken: string): Promise<OAuthTokens> {
    const key = hashToken(refreshToken);
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
      await this.end(connection, "expired after 90 days without use");
      throw new InvalidGrantError("Refresh token expired");
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
      check = await this.method.recheck(connection.upstream);
    } catch (err) {
      check = { ok: false, reason: "unavailable" };
      log(`re-check for ${connection.person.name} failed: ${err instanceof Error ? err.message : "unknown error"}`);
    }

    if (!check.ok && check.reason === "unavailable") {
      log(`login method unavailable while refreshing ${connection.person.name}; refresh token kept`);
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
      extra: { personId: grant.person.id, personName: grant.person.name },
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

  /** Called on shutdown: sessions behind codes that were never exchanged would otherwise be orphaned. */
  async close(): Promise<void> {
    const pending = [...this.codes.values()];
    this.codes.clear();
    this.states.clear();
    await Promise.all(pending.map((c) => this.safeCleanup(c.upstream, c.person)));
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
    this.access.set(hashToken(accessToken), {
      connectionId: connection.id,
      clientId: connection.clientId,
      person: connection.person,
      expiresAt: this.now() + ACCESS_TOKEN_TTL_MS,
    });
    return {
      access_token: accessToken,
      token_type: "bearer",
      expires_in: ACCESS_TOKEN_TTL_MS / 1000,
      refresh_token: refreshToken,
    };
  }

  /** Removes a connection, its access tokens and its upstream session. */
  private async end(connection: Connection, why: string): Promise<void> {
    await this.store.removeConnection(connection.id);
    this.forget(connection.id);
    await this.safeCleanup(connection.upstream, connection.person);
    log(`disconnected ${connection.person.name} (${why})`);
  }

  private forget(connectionId: string): void {
    this.recent.delete(connectionId);
    for (const [key, grant] of this.access) if (grant.connectionId === connectionId) this.access.delete(key);
  }

  private async safeCleanup(upstream: Record<string, unknown>, person: Person): Promise<void> {
    try {
      await this.method.cleanup(upstream);
    } catch (err) {
      log(`cleanup for ${person.name} failed: ${err instanceof Error ? err.message : "unknown error"}`);
    }
  }

  private sweep(): void {
    const t = this.now();
    for (const [key, s] of this.states) if (t - s.createdAt > LOGIN_STATE_TTL_MS) this.states.delete(key);
    for (const [key, c] of this.codes) {
      if (t - c.createdAt > CODE_TTL_MS) {
        this.codes.delete(key);
        void this.safeCleanup(c.upstream, c.person);
      }
    }
    for (const [key, g] of this.access) if (g.expiresAt <= t) this.access.delete(key);
    for (const [key, r] of this.recent) if (t - r.rotatedAt > REFRESH_GRACE_MS) this.recent.delete(key);
  }
}
