// Counts failed sign-in attempts per key over a sliding window, so a guessed password or key costs the guesser time.
// Keys are opaque strings: the sign-in form passes one for the address and one for the username, and either being
// locked refuses the attempt. State is in memory and is lost on restart.

export const MAX_FAILURES = 5;
export const WINDOW_MS = 15 * 60_000;
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
    for (const key of keys) {
      const counted = this.counted(key, now);
      const oldest = counted[0];
      if (oldest !== undefined && counted.length >= MAX_FAILURES) wait = Math.max(wait, oldest + WINDOW_MS - now);
    }
    return wait;
  }

  /** Records one failure against each key. */
  fail(keys: readonly string[]): void {
    const now = this.now();
    this.prune(now);
    for (const key of keys) {
      const counted = this.counted(key, now);
      counted.push(now);
      this.failures.set(key, counted);
    }
  }

  /** How many keys are held. Exists so a test can check that expired keys are dropped. */
  size(): number {
    return this.failures.size;
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
}
