// OpenID Connect as the login method: any standard provider, found through its issuer's discovery document.
// openid-client does the protocol (PKCE, state, nonce, ID token validation, refresh, revocation); this file
// keeps the per-login secrets, applies the allowlist, and sorts failures into "refused" and "unavailable".
// Error messages here are logged by the provider, so they never contain a token, code, nonce, verifier or secret.
import type express from "express";
import * as client from "openid-client";
import type { LoginMethod, RecheckResult } from "./login-method.js";
import type { Person } from "./store.js";

const LOGIN_TTL_MS = 10 * 60 * 1000;
const TIMEOUT_S = 10;
const BASE_SCOPES = ["openid", "email", "profile"];

export type OidcOptions = {
  /** This server's public origin; the redirect URI is `${publicUrl}/login/callback`. */
  publicUrl: string;
  issuer: string;
  clientId: string;
  /** With a secret the client uses client_secret_basic; without, it is a public client relying on PKCE. */
  clientSecret?: string;
  allowedEmails: readonly string[];
  allowedSubjects: readonly string[];
  requiredGroup?: string;
  groupsClaim: string;
  /** Extra authorization query, e.g. "access_type=offline&prompt=consent". */
  authParams?: string;
  now?: () => number;
};

type Upstream = { sub: string; name: string; refreshToken?: string; idTokenExpiresAt: number };

type Pending = { verifier: string; nonce: string; createdAt: number };

type Claims = Record<string, unknown>;

/** The provider answered and said no: a 4xx from its token endpoint. */
class OidcRejected extends Error {}

function isLocalHttp(url: URL): boolean {
  return url.protocol === "http:" && (url.hostname === "localhost" || url.hostname === "127.0.0.1");
}

/** A provider's own error code, safe to log; anything else is left out. */
function safeCode(value: unknown): string {
  return typeof value === "string" && /^[A-Za-z0-9_]{1,60}$/.test(value) ? ` (${value})` : "";
}

/** The HTTP status of an openid-client failure, when the provider answered at all. */
function statusOf(err: unknown): number | undefined {
  if (err instanceof client.ResponseBodyError) return err.status;
  if (err instanceof client.ClientError && err.cause instanceof Response) return err.cause.status;
  return undefined;
}

/**
 * A fixed description of an openid-client failure. Library messages are never passed on as they are:
 * some quote response bodies, and a body can echo a code or token.
 */
function describe(err: unknown, what: string): string {
  if (err instanceof client.ResponseBodyError) return `${what}: the provider answered ${err.status}${safeCode(err.error)}`;
  if (err instanceof client.AuthorizationResponseError) return `${what}: the provider returned an error${safeCode(err.error)}`;
  if (err instanceof client.WWWAuthenticateChallengeError) return `${what}: the provider refused the client's credentials`;
  if (err instanceof client.ClientError) {
    const status = statusOf(err);
    return `${what}: ${status === undefined ? "the provider's answer was not accepted" : `the provider answered ${status}`}${safeCode(err.code)}`;
  }
  if (err instanceof TypeError) return `${what}: the provider could not be reached`;
  if (err instanceof Error && err.name === "TimeoutError") return `${what}: the provider timed out`;
  return `${what}: failed`;
}

function personFrom(claims: Claims, sub: string): Person {
  for (const key of ["name", "preferred_username", "email"]) {
    const v = claims[key];
    if (typeof v === "string" && v.trim()) return { id: sub, name: v };
  }
  return { id: sub, name: sub };
}

export class OidcLogin implements LoginMethod {
  private readonly issuer: URL;
  private readonly insecure: boolean;
  private readonly redirectUri: string;
  private readonly clientId: string;
  private readonly clientSecret: string | undefined;
  private readonly allowedEmails: ReadonlySet<string>;
  private readonly allowedSubjects: ReadonlySet<string>;
  private readonly requiredGroup: string | undefined;
  private readonly groupsClaim: string;
  private readonly authParams: URLSearchParams;
  private readonly now: () => number;
  private readonly pending = new Map<string, Pending>();
  private configuration: Promise<client.Configuration> | undefined;

  constructor(opts: OidcOptions) {
    this.issuer = new URL(opts.issuer);
    // config accepts http only for a local issuer; the method holds to that itself rather than trust config alone
    if (this.issuer.protocol === "http:" && !isLocalHttp(this.issuer))
      throw new Error("an http issuer is allowed only on localhost or 127.0.0.1");
    if (this.issuer.protocol !== "http:" && this.issuer.protocol !== "https:") throw new Error("the issuer must be an https URL");
    this.insecure = isLocalHttp(this.issuer);
    this.redirectUri = `${opts.publicUrl}/login/callback`;
    this.clientId = opts.clientId;
    this.clientSecret = opts.clientSecret || undefined;
    this.allowedEmails = new Set(opts.allowedEmails.map((e) => e.toLowerCase()));
    this.allowedSubjects = new Set(opts.allowedSubjects);
    this.requiredGroup = opts.requiredGroup || undefined;
    this.groupsClaim = opts.groupsClaim;
    this.authParams = new URLSearchParams(opts.authParams ?? "");
    this.now = opts.now ?? Date.now;
  }

  async start(loginState: string, res: express.Response): Promise<void> {
    this.sweep();
    let config: client.Configuration;
    try {
      config = await this.config();
    } catch (err) {
      throw new Error(describe(err, "the provider's discovery document could not be read"));
    }

    const verifier = client.randomPKCECodeVerifier();
    const nonce = client.randomNonce();
    const challenge = await client.calculatePKCECodeChallenge(verifier);
    const supported = config.serverMetadata().scopes_supported ?? [];
    const scopes = supported.includes("offline_access") ? [...BASE_SCOPES, "offline_access"] : BASE_SCOPES;

    const params = new URLSearchParams(this.authParams);
    // the protocol's own parameters always win over anything in authParams
    for (const [k, v] of Object.entries({
      redirect_uri: this.redirectUri,
      scope: scopes.join(" "),
      code_challenge: challenge,
      code_challenge_method: "S256",
      state: loginState,
      nonce,
    }))
      params.set(k, v);

    const url = client.buildAuthorizationUrl(config, params);
    this.pending.set(loginState, { verifier, nonce, createdAt: this.now() });
    res.set("Cache-Control", "no-store").redirect(302, url.href);
  }

  async finish(req: express.Request): Promise<{ person: Person; upstream: Record<string, unknown> } | { refused: string; person?: Person }> {
    this.sweep();
    const loginState = typeof req.query.state === "string" ? req.query.state : "";
    const entry = loginState ? this.pending.get(loginState) : undefined;
    // single use: gone before the provider is asked
    if (entry) this.pending.delete(loginState);
    if (!entry || this.now() - entry.createdAt > LOGIN_TTL_MS) throw new Error("unknown or expired sign-in");

    const currentUrl = new URL(this.redirectUri);
    for (const [k, v] of Object.entries(req.query)) if (typeof v === "string") currentUrl.searchParams.set(k, v);

    let tokens: Awaited<ReturnType<typeof client.authorizationCodeGrant>>;
    let claims: Claims | undefined;
    try {
      const config = await this.config();
      tokens = await client.authorizationCodeGrant(config, currentUrl, {
        pkceCodeVerifier: entry.verifier,
        expectedNonce: entry.nonce,
        expectedState: loginState,
        idTokenExpected: true,
      });
      claims = tokens.claims();
    } catch (err) {
      throw new Error(describe(err, "the sign-in could not be completed"));
    }
    if (!claims) throw new Error("the provider returned no ID token");

    const sub = claims.sub as string;
    const person = personFrom(claims, sub);
    const upstream: Upstream = {
      sub,
      name: person.name,
      idTokenExpiresAt: (claims.exp as number) * 1000,
      ...(tokens.refresh_token ? { refreshToken: tokens.refresh_token } : {}),
    };

    if (!this.allowed(claims)) {
      try {
        await this.cleanup(upstream);
      } catch {
        // best effort: the refusal is shown regardless, and the provider's session ends at its own expiry
      }
      return { refused: `${person.name} is not allowed to use LubeLogger MCP.`, person };
    }
    return { person, upstream };
  }

  async recheck(upstream: Record<string, unknown>): Promise<RecheckResult> {
    const sub = upstream.sub;
    const expiresAt = upstream.idTokenExpiresAt;
    if (typeof sub !== "string" || !sub || typeof expiresAt !== "number") return { ok: false, reason: "refused" };
    const name = typeof upstream.name === "string" && upstream.name ? upstream.name : sub;
    const refreshToken = typeof upstream.refreshToken === "string" && upstream.refreshToken ? upstream.refreshToken : undefined;
    const old: Upstream = { sub, name, idTokenExpiresAt: expiresAt, ...(refreshToken ? { refreshToken } : {}) };

    // no refresh token: the connection lives exactly as long as the ID token it started with
    if (!refreshToken) {
      if (this.now() >= expiresAt) return { ok: false, reason: "refused" };
      return { ok: true, upstream: old, person: { id: sub, name } };
    }

    let config: client.Configuration;
    try {
      config = await this.config();
    } catch {
      // discovery failing is never a verdict on the person, whatever status it answered
      return { ok: false, reason: "unavailable" };
    }

    let tokens: Awaited<ReturnType<typeof client.refreshTokenGrant>>;
    try {
      tokens = await client.refreshTokenGrant(config, refreshToken);
    } catch (err) {
      const status = statusOf(err);
      return { ok: false, reason: status !== undefined && status >= 400 && status < 500 ? "refused" : "unavailable" };
    }

    const nextRefresh = tokens.refresh_token || refreshToken;
    const claims: Claims | undefined = tokens.claims();
    if (!claims) {
      // no new ID token: the old claims stand, but only while the old ID token is still valid
      if (this.now() >= expiresAt) return { ok: false, reason: "refused" };
      return { ok: true, upstream: { ...old, refreshToken: nextRefresh }, person: { id: sub, name } };
    }

    if (claims.sub !== sub || !this.allowed(claims)) return { ok: false, reason: "refused" };
    const person = personFrom(claims, sub);
    const next: Upstream = { sub, name: person.name, refreshToken: nextRefresh, idTokenExpiresAt: (claims.exp as number) * 1000 };
    return { ok: true, upstream: next, person };
  }

  async cleanup(upstream: Record<string, unknown>): Promise<void> {
    const token = upstream.refreshToken;
    if (typeof token !== "string" || !token) return;
    let config: client.Configuration;
    try {
      config = await this.config();
    } catch (err) {
      throw new Error(describe(err, "the refresh token could not be revoked"));
    }
    if (!config.serverMetadata().revocation_endpoint) return;
    try {
      await client.tokenRevocation(config, token, { token_type_hint: "refresh_token" });
    } catch (err) {
      throw new Error(describe(err, "the refresh token could not be revoked"));
    }
  }

  /** Allowed by a verified listed email, a listed subject, or the required group in the groups claim. */
  private allowed(claims: Claims): boolean {
    const email = claims.email;
    if (typeof email === "string" && claims.email_verified === true && this.allowedEmails.has(email.toLowerCase())) return true;
    if (typeof claims.sub === "string" && this.allowedSubjects.has(claims.sub)) return true;
    const groups = claims[this.groupsClaim];
    if (this.requiredGroup !== undefined && Array.isArray(groups) && groups.includes(this.requiredGroup)) return true;
    return false;
  }

  /** The provider's configuration, discovered on first use and cached; a failed discovery is retried next time. */
  private config(): Promise<client.Configuration> {
    if (!this.configuration) {
      const execute: Array<(c: client.Configuration) => void> = [client.enableNonRepudiationChecks];
      if (this.insecure) execute.push(client.allowInsecureRequests);
      const p = client.discovery(
        this.issuer,
        this.clientId,
        this.clientSecret ? { client_secret: this.clientSecret } : undefined,
        this.clientSecret ? client.ClientSecretBasic(this.clientSecret) : client.None(),
        { execute, timeout: TIMEOUT_S },
      );
      this.configuration = p;
      p.catch(() => {
        if (this.configuration === p) this.configuration = undefined;
      });
    }
    return this.configuration;
  }

  private sweep(): void {
    const t = this.now();
    for (const [key, p] of this.pending) if (t - p.createdAt > LOGIN_TTL_MS) this.pending.delete(key);
  }
}
