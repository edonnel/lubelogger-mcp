import { randomBytes } from "node:crypto";
import type { RecordKind } from "./lubelogger.js";

/** A LubeLogger record type, or a reminder to add or update. */
export type PendingKind = RecordKind | "reminder" | "reminderUpdate";

export interface PendingRecord {
  token: string;
  kind: PendingKind;
  vehicleId: number;
  vehicleLabel: string;
  /** Exact body that will be sent to LubeLogger on commit. */
  body: Record<string, unknown>;
  /** True when body replaces an existing record of this kind instead of adding one. */
  update?: boolean;
  /** Who proposed it; only they can commit it. "token" in token mode, "<method>:<person id>" in OAuth modes. */
  owner: string;
  createdAt: number;
}

const MAX_PENDING = 100;

/**
 * Holds proposed records until the user confirms them. What the user was shown is exactly
 * what gets written: commit sends the stored body, never re-derived input.
 */
export class PendingStore {
  private readonly items = new Map<string, PendingRecord>();

  constructor(private readonly ttlMs: number) {}

  add(rec: Omit<PendingRecord, "token" | "createdAt">): PendingRecord {
    this.sweep();
    while (this.items.size >= MAX_PENDING) {
      const oldest = this.items.keys().next().value;
      if (oldest === undefined) break;
      this.items.delete(oldest);
    }
    const full: PendingRecord = { ...rec, token: randomBytes(6).toString("hex"), createdAt: Date.now() };
    this.items.set(full.token, full);
    return full;
  }

  /**
   * Removes and returns the record (single use). Undefined if unknown, expired, or proposed by someone else;
   * someone else's record stays in place for its owner.
   */
  take(token: string, owner: string): PendingRecord | undefined {
    this.sweep();
    const rec = this.items.get(token.trim().toLowerCase());
    if (!rec || rec.owner !== owner) return undefined;
    this.items.delete(rec.token);
    return rec;
  }

  /** Put a record back after a definitive rejection so the user can retry without re-proposing. */
  restore(rec: PendingRecord): void {
    this.items.set(rec.token, rec);
  }

  private sweep(): void {
    const now = Date.now();
    for (const [token, rec] of this.items) {
      if (now - rec.createdAt > this.ttlMs) this.items.delete(token);
    }
  }
}
