// The gate in front of a LubeLogger sign-in form: reads the posted fields, refuses an attempt while its address or
// username is locked or enough attempts on it are still being checked, runs the login method's check, and records a
// wrong answer against the limiter. It decides nothing about pages or login state: the provider turns the outcome
// into a response. Nothing typed is ever logged here.
import type express from "express";
import type { FormCheckResult, FormFields, FormLoginMethod } from "./login-method.js";
import { addressKey, FailureLimiter, MAX_FAILURES, MAX_KEY_LENGTH } from "./rate-limit.js";

/** Shown when a form post is refused only because enough attempts on its keys are still being checked. */
export const STILL_CHECKING = "A sign-in is still being checked. Try again in a moment.";

/** The longest username, password or key read from a sign-in form; anything longer is cut, never sent whole. */
const MAX_FIELD_LENGTH = 512;

// fields: what was read from the form. username: the only field that is ever shown or logged, for the password form.
// outcome: the method's answer; { locked } carries the message to show (a 429) and nothing was sent to LubeLogger;
// { failed } means the check threw, and nothing was counted.
export type FormAttempt = {
  fields: FormFields;
  username?: string;
  outcome: FormCheckResult | { locked: string } | { failed: true };
};

export class FormLoginGate {
  // form sign-ins being checked right now, by limiter key; a key is removed when its count drops to 0
  private readonly inFlight = new Map<string, number>();

  constructor(private readonly limiter: FailureLimiter) {}

  async attempt(req: express.Request, method: FormLoginMethod): Promise<FormAttempt> {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const field = (key: string) => {
      const value = body[key];
      return typeof value === "string" ? value.slice(0, MAX_FIELD_LENGTH) : "";
    };
    // each form fills only its own fields; the username is the only one ever shown again
    const username = method.form === "password" ? field("username") : undefined;
    const fields: FormFields =
      method.form === "password" ? { username, password: field("password") } : { apiKey: field("apiKey") };

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
      const minutes = Math.ceil(wait / 60_000);
      // nothing is sent to LubeLogger, and this refusal is not itself counted as a failure
      // a lock names the minutes until the key is free; attempts still in flight may yet succeed, so no wait is known
      const locked = wait > 0 ? `Too many attempts. Try again in ${minutes} ${minutes === 1 ? "minute" : "minutes"}.` : STILL_CHECKING;
      return { fields, username, outcome: { locked } };
    }

    let result: FormCheckResult;
    for (const key of keys) this.inFlight.set(key, (this.inFlight.get(key) ?? 0) + 1);
    try {
      result = await method.check(fields);
    } catch {
      // the error is left out: it could carry what was typed
      return { fields, username, outcome: { failed: true } };
    } finally {
      // runs before the failure below is recorded, with no await between, so no attempt is counted twice or not at all
      for (const key of keys) {
        const left = (this.inFlight.get(key) ?? 1) - 1;
        if (left > 0) this.inFlight.set(key, left);
        else this.inFlight.delete(key);
      }
    }

    if ("invalid" in result) this.limiter.fail(keys);
    return { fields, username, outcome: result };
  }
}
