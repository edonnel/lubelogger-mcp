// The "who are you" step of the OAuth flow, one implementation per AUTH_MODE.
// The provider owns everything OAuth; a login method only identifies a person and keeps their upstream session.
import type express from "express";
import type { Person } from "./store.js";

export type RecheckResult =
  | { ok: true; upstream: Record<string, unknown>; person: Person }
  | { ok: false; reason: "refused" | "unavailable" };

// The provider logs the message of any error these throw, so messages must never contain a token, code or key.
export interface LoginMethod {
  /** Send the browser to the login. `loginState` must come back as the `state` query parameter of /login/callback. */
  start(loginState: string, res: express.Response): Promise<void>;
  /**
   * Read the browser's return to /login/callback. A refusal message is shown to the person and logged
   * with `person`'s name when the method knows who was refused, so it holds no secret.
   * Any session created for a refused person is cleaned up here.
   */
  finish(
    req: express.Request,
  ): Promise<{ person: Person; upstream: Record<string, unknown> } | { refused: string; person?: Person }>;
  /** Re-check the person on each refresh. "unavailable" is for network errors and 5xx answers only. */
  recheck(upstream: Record<string, unknown>): Promise<RecheckResult>;
  /** End the upstream session of a connection that is going away. */
  cleanup(upstream: Record<string, unknown>): Promise<void>;
}

/** What a person typed into a sign-in form. Each form fills only its own fields. */
export type FormFields = { username?: string; password?: string; apiKey?: string };

// Every message here may be shown on a page and logged, so none ever contains a typed password or key.
export type FormCheckResult =
  | { person: Person; upstream: Record<string, unknown> } // signed in
  | { invalid: string } // wrong credentials: re-show the form, counts as a failure
  | { refused: string; person?: Person } // real credentials, not allowed: "Not allowed" page
  | { unavailable: string }; // LubeLogger unreachable or 5xx: try again shortly

/** A login method that checks typed credentials on the sign-in screen instead of redirecting. */
export interface FormLoginMethod {
  readonly form: "password" | "key";
  check(fields: FormFields): Promise<FormCheckResult>;
  /** Re-check the person on each refresh. "unavailable" is for network errors and 5xx answers only. */
  recheck(upstream: Record<string, unknown>): Promise<RecheckResult>;
  /** End the upstream session of a connection that is going away. */
  cleanup(upstream: Record<string, unknown>): Promise<void>;
}

export type AnyLoginMethod = LoginMethod | FormLoginMethod;

export const isFormMethod = (m: AnyLoginMethod): m is FormLoginMethod => "check" in m;
