// Counts failed sign-in attempts per key over a sliding window, so a guessed password or key costs the guesser time.
// Keys are opaque strings: the sign-in form passes one for the address and one for the username, and either being
// locked refuses the attempt. State is in memory and is lost on restart.

export const MAX_FAILURES = 5;
export const WINDOW_MS = 15 * 60_000;
/** The most keys held at once. Past it, the oldest key that is not locked makes room. */
export const MAX_KEYS = 50_000;
/** Keys are cut to this length, so a long username cannot make a key arbitrarily large. */
export const MAX_KEY_LENGTH = 200;
const PRUNE_EVERY_MS = 60_000;

export class FailureLimiter {
  private readonly failures = new Map<string, number[]>();
  private lastPrune: number;

  constructor(private readonly now: () => number = Date.now) {
    this.lastPrune = now();
  }

  /** Milliseconds until every given key is free again, or 0 when none is locked. */
  lockedFor(keys: readonly string[]): number {
    const now = this.now();
    let wait = 0;
    for (const raw of keys) {
      const counted = this.counted(raw.slice(0, MAX_KEY_LENGTH), now);
      const oldest = counted[0];
      if (oldest !== undefined && counted.length >= MAX_FAILURES) wait = Math.max(wait, oldest + WINDOW_MS - now);
    }
    return wait;
  }

  /** Records one failure against each key. */
  fail(keys: readonly string[]): void {
    const now = this.now();
    this.prune(now);
    for (const raw of keys) {
      const key = raw.slice(0, MAX_KEY_LENGTH);
      if (!this.failures.has(key) && this.failures.size >= MAX_KEYS && !this.makeRoom(now)) continue;
      // only the newest MAX_FAILURES matter: the oldest of them decides when a locked key is free
      const counted = this.counted(key, now).slice(1 - MAX_FAILURES);
      counted.push(now);
      this.failures.set(key, counted);
    }
  }

  /** How many failures of a key are still inside the window. Read only. */
  failureCount(key: string): number {
    return this.counted(key.slice(0, MAX_KEY_LENGTH), this.now()).length;
  }

  /** How many keys are held. Exists so a test can check that keys are dropped. */
  size(): number {
    return this.failures.size;
  }

  /** How many timestamps are held for a key. Exists so a test can check they stay capped. */
  held(key: string): number {
    return this.failures.get(key.slice(0, MAX_KEY_LENGTH))?.length ?? 0;
  }

  /** The failures of a key that are still inside the window, oldest first. */
  private counted(key: string, now: number): number[] {
    return (this.failures.get(key) ?? []).filter((at) => now - at < WINDOW_MS);
  }

  private prune(now: number): void {
    if (now - this.lastPrune < PRUNE_EVERY_MS) return;
    this.lastPrune = now;
    for (const [key, times] of this.failures) {
      if (!times.some((at) => now - at < WINDOW_MS)) this.failures.delete(key);
    }
  }

  /** Frees one slot: expired keys first (swept at most once a minute, so a flood cannot force a scan per request), then the oldest key that is not locked. False when every key is locked. */
  private makeRoom(now: number): boolean {
    this.prune(now);
    if (this.failures.size < MAX_KEYS) return true;
    for (const [key, times] of this.failures) {
      if (times.filter((at) => now - at < WINDOW_MS).length < MAX_FAILURES) {
        this.failures.delete(key);
        return true;
      }
    }
    return false;
  }
}
