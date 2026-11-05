// LubeLogger's own accounts as login methods: a username and password, or a person's own API key.
// Both are checked through LubeLogger's /api/whoami, and the person is whoever LubeLogger says the credentials belong to.
// With LubeLogger's login switched off, whoami answers root "admin" to anything, so each method first asks it with no
// credentials and refuses if that succeeds. Messages here are shown on pages and logged: none contains a password or key.
import type { FormCheckResult, FormFields, FormLoginMethod, RecheckResult } from "./login-method.js";

export const WRONG_PASSWORD = "That username or password is wrong.";
export const WRONG_KEY = "That API key is not valid.";
export const LOGIN_OFF =
  "LubeLogger's own login is turned off, so it can't confirm who you are. Turn it on in LubeLogger's settings.";
export const UNAVAILABLE = "LubeLogger can't be reached right now. Try again shortly.";
export const notAllowed = (username: string) => `${username} is not allowed to use LubeLogger MCP.`;

type WhoamiOptions = { lubeloggerUrl: string; timeoutMs: number };

/** Asks LubeLogger who the given credentials belong to. Throws only when LubeLogger could not be asked. */
class Whoami {
  private readonly url: string;
  private readonly timeoutMs: number;

  constructor(opts: WhoamiOptions) {
    this.url = `${opts.lubeloggerUrl.replace(/\/+$/, "")}/api/whoami`;
    this.timeoutMs = opts.timeoutMs;
  }

  async ask(headers: Record<string, string>): Promise<{ status: number; username?: string }> {
    let r: Response;
    try {
      r = await fetch(this.url, {
        headers: { ...headers, "culture-invariant": "true", accept: "application/json" },
        redirect: "error",
        signal: AbortSignal.timeout(this.timeoutMs),
      });
    } catch {
      // the cause is left out: it can carry the request, and so its credentials
      throw new Error("LubeLogger could not be reached");
    }

    if (r.status !== 200) {
      await r.body?.cancel().catch(() => undefined);
      return { status: r.status };
    }
    let body: unknown;
    try {
      body = await r.json();
    } catch {
      body = undefined;
    }
    const username = typeof body === "object" && body !== null ? (body as { username?: unknown }).username : undefined;
    return { status: 200, username: typeof username === "string" && username ? username : undefined };
  }

  /**
   * Whether LubeLogger's login is switched off: whoami with no credentials succeeds only then.
   * Returns "unavailable" when that can't be told.
   */
  async loginIsOff(): Promise<boolean | "unavailable"> {
    let status: number;
    try {
      ({ status } = await this.ask({}));
    } catch {
      return "unavailable";
    }
    if (status === 200) return true;
    return status >= 500 ? "unavailable" : false;
  }
}

/**
 * Sorts a whoami answer for credentials into the person, "rejected" (a 4xx: LubeLogger said no) or
 * "unavailable" (a 5xx, a 200 without a username, or no answer at all).
 */
async function identify(
  whoami: Whoami,
  headers: Record<string, string>,
): Promise<{ user: string } | { rejected: true } | { unavailable: true }> {
  let answer: { status: number; username?: string };
  try {
    answer = await whoami.ask(headers);
  } catch {
    return { unavailable: true };
  }
  if (answer.status === 200) return answer.username ? { user: answer.username } : { unavailable: true };
  return answer.status >= 400 && answer.status < 500 ? { rejected: true } : { unavailable: true };
}

export type LubeLoggerPasswordOptions = WhoamiOptions & {
  /** LubeLogger usernames allowed to connect, as LubeLogger spells them. */
  allowedUsers: string[];
};

/**
 * A LubeLogger username and password. The password is sent once, to whoami, and never kept:
 * the upstream holds only the username, and a refresh re-checks the allowlist alone.
 */
export class LubeLoggerPasswordLogin implements FormLoginMethod {
  readonly form = "password" as const;
  private readonly whoami: Whoami;
  private readonly allowedUsers: ReadonlySet<string>;

  constructor(opts: LubeLoggerPasswordOptions) {
    this.whoami = new Whoami(opts);
    this.allowedUsers = new Set(opts.allowedUsers);
  }

  async check(fields: FormFields): Promise<FormCheckResult> {
    const { username, password } = fields;
    if (!username || !password) return { invalid: WRONG_PASSWORD };
    // LubeLogger splits Basic credentials on ":", so a colon in either can never sign in
    if (username.includes(":") || password.includes(":")) return { invalid: WRONG_PASSWORD };

    const off = await this.whoami.loginIsOff();
    if (off === "unavailable") return { unavailable: UNAVAILABLE };
    if (off) return { refused: LOGIN_OFF };

    const basic = Buffer.from(`${username}:${password}`, "utf8").toString("base64");
    const answer = await identify(this.whoami, { authorization: `Basic ${basic}` });
    if ("unavailable" in answer) return { unavailable: UNAVAILABLE };
    if ("rejected" in answer) return { invalid: WRONG_PASSWORD };

    const who = answer.user;
    const person = { id: who, name: who };
    if (!this.allowedUsers.has(who)) return { refused: notAllowed(who), person };
    return { person, upstream: { username: who } };
  }

  async recheck(upstream: Record<string, unknown>): Promise<RecheckResult> {
    const username = upstream.username;
    if (typeof username !== "string" || !this.allowedUsers.has(username)) return { ok: false, reason: "refused" };
    return { ok: true, upstream: { username }, person: { id: username, name: username } };
  }

  async cleanup(): Promise<void> {
    // a password sign-in leaves nothing in LubeLogger to end
  }
}

export type LubeLoggerKeyOptions = WhoamiOptions;

/**
 * A person's own LubeLogger API key. Any LubeLogger user may connect with one, and the connection then
 * acts with that key, so it never gains more than the person already has. A refresh asks whoami again.
 */
export class LubeLoggerKeyLogin implements FormLoginMethod {
  readonly form = "key" as const;
  private readonly whoami: Whoami;

  constructor(opts: LubeLoggerKeyOptions) {
    this.whoami = new Whoami(opts);
  }

  async check(fields: FormFields): Promise<FormCheckResult> {
    const apiKey = fields.apiKey;
    if (!apiKey) return { invalid: WRONG_KEY };

    const off = await this.whoami.loginIsOff();
    if (off === "unavailable") return { unavailable: UNAVAILABLE };
    if (off) return { refused: LOGIN_OFF };

    const answer = await identify(this.whoami, { "x-api-key": apiKey });
    if ("unavailable" in answer) return { unavailable: UNAVAILABLE };
    if ("rejected" in answer) return { invalid: WRONG_KEY };
    const who = answer.user;
    return { person: { id: who, name: who }, upstream: { username: who, apiKey } };
  }

  async recheck(upstream: Record<string, unknown>): Promise<RecheckResult> {
    const { username, apiKey } = upstream;
    if (typeof username !== "string" || !username || typeof apiKey !== "string" || !apiKey)
      return { ok: false, reason: "refused" };

    const off = await this.whoami.loginIsOff();
    if (off === "unavailable") return { ok: false, reason: "unavailable" };
    if (off) return { ok: false, reason: "refused" };

    const answer = await identify(this.whoami, { "x-api-key": apiKey });
    if ("unavailable" in answer) return { ok: false, reason: "unavailable" };
    // a rejected key was deleted; a key now owned by someone else is not this connection's person
    if ("rejected" in answer || answer.user !== username) return { ok: false, reason: "refused" };
    return { ok: true, upstream: { username, apiKey }, person: { id: username, name: username } };
  }

  async cleanup(): Promise<void> {
    // the server never deletes a person's API key in LubeLogger
  }
}
