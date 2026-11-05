// Counts failed sign-in attempts per key over a sliding window, so a guessed password or key costs the guesser time.
// Keys are opaque strings: the sign-in form passes one for the address and one for the username, and either being
// locked refuses the attempt. State is in memory and is lost on restart.
//
// Memory is bounded by failing closed: a key with a failure still in the window is never dropped, so a flood of junk
// keys cannot reset anyone's count. When the map is full, a key that is not already held is treated as locked until
// failures expire and make room.

export const MAX_FAILURES = 5;
export const WINDOW_MS = 15 * 60_000;
/** The most keys held at once. Past it, keys not already held are refused until room is freed. */
export const MAX_KEYS = 50_000;
/** Keys are cut to this length, so a long username cannot make a key arbitrarily large. */
export const MAX_KEY_LENGTH = 200;
const PRUNE_EVERY_MS = 60_000;

/**
 * The limiter key for a client address. IPv4 is kept as it is, an IPv4-mapped IPv6 address becomes its IPv4 form,
 * and other IPv6 addresses are cut to their /64 network, since one client can use any address in its /64.
 */
export function addressKey(ip: string | undefined): string {
  if (!ip) return "addr:unknown";
  if (!ip.includes(":")) return `addr:${ip}`;
  const groups = ipv6Groups(ip);
  if (!groups) return `addr:${ip.toLowerCase()}`;
  if (groups.slice(0, 5).every((g) => g === 0) && groups[5] === 0xffff) {
    const [hi = 0, lo = 0] = groups.slice(6);
    return `addr:${hi >> 8}.${hi & 0xff}.${lo >> 8}.${lo & 0xff}`;
  }
  return `addr:${groups
    .slice(0, 4)
    .map((g) => g.toString(16))
    .join(":")}::/64`;
}

/** The eight 16-bit groups of an IPv6 address, or undefined when it is not one. */
function ipv6Groups(ip: string): number[] | undefined {
  const address = ip.split("%")[0] ?? "";
  const halves = address.split("::");
  if (halves.length > 2) return undefined;
  const parse = (half: string | undefined): number[] | undefined => {
    if (!half) return [];
    const out: number[] = [];
    const parts = half.split(":");
    for (const [i, part] of parts.entries()) {
      // a dotted IPv4 tail fills the last two groups
      if (i === parts.length - 1 && part.includes(".")) {
        const octets = part.split(".");
        if (octets.length !== 4 || !octets.every((o) => /^\d{1,3}$/.test(o) && Number(o) <= 255)) return undefined;
        const [a, b, c, d] = octets.map(Number) as [number, number, number, number];
        out.push((a << 8) | b, (c << 8) | d);
      } else if (/^[0-9a-f]{1,4}$/i.test(part)) out.push(parseInt(part, 16));
      else return undefined;
    }
    return out;
  };
  const head = parse(halves[0]);
  const tail = parse(halves[1]);
  if (!head || !tail) return undefined;
  if (halves.length === 1) return head.length === 8 ? head : undefined;
  const missing = 8 - head.length - tail.length;
  return missing >= 1 ? [...head, ...new Array<number>(missing).fill(0), ...tail] : undefined;
}

export class FailureLimiter {
  private readonly failures = new Map<string, number[]>();
  private lastPrune: number;
  /** The oldest failure still in the window when the map was last pruned, if any. */
  private oldestAtPrune: number | undefined;

  constructor(private readonly now: () => number = Date.now) {
    this.lastPrune = now();
  }

  /**
   * Milliseconds until every given key is free again, or 0 when none is locked. While the map is full, a key that
   * is not held counts as locked, until the oldest held failure expires (or for a whole window when that is unknown).
   */
  lockedFor(keys: readonly string[]): number {
    const now = this.now();
    // only a full map needs pruning here: it is what lets new keys in again once a flood has passed
    if (this.failures.size >= MAX_KEYS) this.prune(now);
    const saturated = this.failures.size >= MAX_KEYS;
    let wait = 0;
    for (const raw of keys) {
      const key = raw.slice(0, MAX_KEY_LENGTH);
      if (saturated && !this.failures.has(key)) {
        wait = Math.max(wait, this.saturatedWait(now));
        continue;
      }
      const counted = this.counted(key, now);
      const oldest = counted[0];
      if (oldest !== undefined && counted.length >= MAX_FAILURES) wait = Math.max(wait, oldest + WINDOW_MS - now);
    }
    return wait;
  }

  /** Records one failure against each key. A key not already held is not added while the map is full. */
  fail(keys: readonly string[]): void {
    const now = this.now();
    this.prune(now);
    for (const raw of keys) {
      const key = raw.slice(0, MAX_KEY_LENGTH);
      if (!this.failures.has(key) && this.failures.size >= MAX_KEYS) continue;
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

  /** Drops keys whose failures have all expired. At most once a minute, so a flood cannot force a scan per request. */
  private prune(now: number): void {
    if (now - this.lastPrune < PRUNE_EVERY_MS) return;
    this.lastPrune = now;
    let oldest: number | undefined;
    for (const [key, times] of this.failures) {
      const live = times.find((at) => now - at < WINDOW_MS);
      if (live === undefined) this.failures.delete(key);
      else if (oldest === undefined || live < oldest) oldest = live;
    }
    this.oldestAtPrune = oldest;
  }

  /** How long a key that is not held must wait while the map is full. */
  private saturatedWait(now: number): number {
    const left = this.oldestAtPrune === undefined ? 0 : this.oldestAtPrune + WINDOW_MS - now;
    return left > 0 ? left : WINDOW_MS;
  }
}
