// Home Assistant as the login method: HA's own login page, then any HA administrator may connect.
// The HA refresh token is the upstream session; each refresh renews it and re-reads auth/current_user,
// so deleting the session in HA or removing admin rights ends the connection within the hour.
// Error messages here are logged by the provider, so they never contain a token or code.
import type express from "express";
import type { LoginMethod, RecheckResult } from "./login-method.js";
import type { Person } from "./store.js";

const TIMEOUT_MS = 10_000;

export const NOT_ADMIN = "Only Home Assistant administrators can connect.";

export type HomeAssistantOptions = {
  /** This server's public origin; HA's client ID is `publicUrl + "/"`. */
  publicUrl: string;
  /** Where the browser reaches HA. */
  haPublicUrl: string;
  /** Where this server reaches HA. */
  haUrl: string;
  fetch?: typeof fetch;
};

type HaUser = { id: string; name: string; is_admin: boolean };

/** HA answered and said no (a 400 from the token endpoint, or auth_invalid on the WebSocket). */
class HaRejected extends Error {}

/** HA could not be asked: a network error, a timeout, a 5xx, or a broken WebSocket exchange. */
class HaUnavailable extends Error {}

function isUser(value: unknown): value is HaUser {
  if (typeof value !== "object" || value === null) return false;
  const u = value as Record<string, unknown>;
  return typeof u.id === "string" && typeof u.name === "string" && typeof u.is_admin === "boolean";
}

export class HomeAssistantLogin implements LoginMethod {
  private readonly clientId: string;
  private readonly redirectUri: string;
  private readonly haPublicUrl: string;
  private readonly haUrl: string;
  private readonly wsUrl: string;
  private readonly fetch: typeof fetch;

  constructor(opts: HomeAssistantOptions) {
    this.clientId = `${opts.publicUrl}/`;
    this.redirectUri = `${opts.publicUrl}/login/callback`;
    this.haPublicUrl = opts.haPublicUrl;
    this.haUrl = opts.haUrl;
    const ws = new URL("/api/websocket", opts.haUrl);
    ws.protocol = ws.protocol === "https:" ? "wss:" : "ws:";
    this.wsUrl = ws.href;
    const f = opts.fetch ?? fetch;
    this.fetch = (input, init) => f(input, init);
  }

  async start(loginState: string, res: express.Response): Promise<void> {
    const q = new URLSearchParams({
      response_type: "code",
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      state: loginState,
    });
    res.set("Cache-Control", "no-store").redirect(302, `${this.haPublicUrl}/auth/authorize?${q}`);
  }

  async finish(req: express.Request): Promise<{ person: Person; upstream: Record<string, unknown> } | { refused: string; person?: Person }> {
    const code = typeof req.query.code === "string" ? req.query.code : "";
    if (!code) throw new Error("Home Assistant returned no authorization code");

    const tokens = await this.token({ grant_type: "authorization_code", code, client_id: this.clientId });
    if (!tokens.refreshToken) throw new Error("Home Assistant returned no refresh token");
    const upstream = { haRefreshToken: tokens.refreshToken };

    let user: HaUser;
    try {
      user = await this.currentUser(tokens.accessToken);
    } catch (err) {
      // the session was created; it must not outlive this failed login
      await this.cleanup(upstream);
      throw err;
    }

    const person = { id: user.id, name: user.name };
    if (user.is_admin !== true) {
      await this.cleanup(upstream);
      return { refused: NOT_ADMIN, person };
    }
    return { person, upstream };
  }

  async recheck(upstream: Record<string, unknown>): Promise<RecheckResult> {
    const haRefreshToken = upstream.haRefreshToken;
    if (typeof haRefreshToken !== "string" || !haRefreshToken) return { ok: false, reason: "refused" };

    let user: HaUser;
    try {
      const { accessToken } = await this.token({
        grant_type: "refresh_token",
        refresh_token: haRefreshToken,
        client_id: this.clientId,
      });
      user = await this.currentUser(accessToken);
    } catch (err) {
      return { ok: false, reason: err instanceof HaRejected ? "refused" : "unavailable" };
    }

    if (user.is_admin !== true) return { ok: false, reason: "refused" };
    // HA refresh tokens don't rotate: the same one stays the upstream session
    return { ok: true, upstream: { haRefreshToken }, person: { id: user.id, name: user.name } };
  }

  async cleanup(upstream: Record<string, unknown>): Promise<void> {
    const token = upstream.haRefreshToken;
    if (typeof token !== "string" || !token) return;
    try {
      const r = await this.fetch(`${this.haUrl}/auth/revoke`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({ token }).toString(),
        redirect: "error",
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      await r.body?.cancel();
    } catch {
      // best effort: an unreachable HA cannot be told, and the connection is going away regardless
    }
  }

  /** POST to HA's token endpoint. Throws HaRejected for a 400/401/403 answer, HaUnavailable otherwise. */
  private async token(fields: Record<string, string>): Promise<{ accessToken: string; refreshToken?: string }> {
    let r: Response;
    try {
      r = await this.fetch(`${this.haUrl}/auth/token`, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams(fields).toString(),
        redirect: "error",
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
    } catch (err) {
      const why = err instanceof Error && err.name === "TimeoutError" ? "timed out" : "could not be reached";
      throw new HaUnavailable(`Home Assistant's token endpoint ${why}`);
    }

    let body: unknown;
    try {
      body = await r.json();
    } catch {
      body = undefined;
    }

    if (r.status === 400 || r.status === 401 || r.status === 403) {
      const error = typeof body === "object" && body !== null ? (body as { error?: unknown }).error : undefined;
      // HA's own error codes are safe to log; anything else is left out
      const code = typeof error === "string" && /^[a-z_]{1,40}$/.test(error) ? ` (${error})` : "";
      throw new HaRejected(`Home Assistant's token endpoint refused the request: ${r.status}${code}`);
    }
    if (!r.ok) throw new HaUnavailable(`Home Assistant's token endpoint answered ${r.status}`);

    const t = (typeof body === "object" && body !== null ? body : {}) as Record<string, unknown>;
    if (typeof t.access_token !== "string" || !t.access_token)
      throw new HaUnavailable("Home Assistant's token endpoint returned no access token");
    return {
      accessToken: t.access_token,
      refreshToken: typeof t.refresh_token === "string" && t.refresh_token ? t.refresh_token : undefined,
    };
  }

  /** auth/current_user over HA's WebSocket API. The socket is closed on every outcome. */
  private currentUser(accessToken: string): Promise<HaUser> {
    return new Promise((resolve, reject) => {
      let ws: WebSocket;
      try {
        ws = new WebSocket(this.wsUrl);
      } catch {
        reject(new HaUnavailable("Home Assistant's WebSocket could not be opened"));
        return;
      }

      let settled = false;
      const done = (err: Error | undefined, user?: HaUser) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try {
          ws.close();
        } catch {
          // already closing or closed
        }
        if (err) reject(err);
        else resolve(user as HaUser);
      };
      const timer = setTimeout(() => done(new HaUnavailable("Home Assistant's WebSocket did not answer in time")), TIMEOUT_MS);

      ws.addEventListener("message", (event) => {
        let msg: Record<string, unknown>;
        try {
          const parsed: unknown = JSON.parse(String(event.data));
          if (typeof parsed !== "object" || parsed === null) throw new Error("not an object");
          msg = parsed as Record<string, unknown>;
        } catch {
          done(new HaUnavailable("Home Assistant sent an unreadable WebSocket message"));
          return;
        }
        switch (msg.type) {
          case "auth_required":
            ws.send(JSON.stringify({ type: "auth", access_token: accessToken }));
            break;
          case "auth_ok":
            ws.send(JSON.stringify({ id: 1, type: "auth/current_user" }));
            break;
          case "auth_invalid":
            done(new HaRejected("Home Assistant rejected the access token"));
            break;
          case "result":
            if (msg.id !== 1) break;
            if (msg.success === true && isUser(msg.result)) done(undefined, msg.result);
            else done(new HaUnavailable("Home Assistant did not return the current user"));
            break;
        }
      });
      ws.addEventListener("error", () => done(new HaUnavailable("Home Assistant's WebSocket connection failed")));
      ws.addEventListener("close", () => done(new HaUnavailable("Home Assistant closed the WebSocket early")));
    });
  }
}
