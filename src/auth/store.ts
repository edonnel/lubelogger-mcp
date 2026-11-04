// Persistent OAuth state: registered clients and per-person connections.
// Refresh tokens are kept only as SHA-256 hashes. Nothing here logs a secret.
import { createHash } from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import type { OAuthClientInformationFull } from "@modelcontextprotocol/sdk/shared/auth.js";

export const REFRESH_GRACE_MS = 60_000;
export const IDLE_EXPIRY_MS = 90 * 24 * 60 * 60 * 1000;

const FILE_NAME = "oauth.json";

export type Person = { id: string; name: string };

export type Connection = {
  id: string;
  clientId: string;
  person: Person;
  upstream: Record<string, unknown>;
  refreshHash: string;
  previousRefreshHash?: string;
  rotatedAt?: number;
  lastUsedAt: number;
};

// Maps, not plain objects: keys come from outside (client_id), and a plain
// object would answer "constructor" or "__proto__" with inherited members
type Data = {
  clients: Map<string, OAuthClientInformationFull>;
  connections: Map<string, Connection>;
};

export function hashToken(t: string): string {
  return createHash("sha256").update(t).digest("hex");
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export class AuthStore {
  private writes: Promise<void> = Promise.resolve();

  private constructor(
    private readonly file: string,
    private readonly data: Data,
    private readonly now: () => number,
  ) {}

  static async open(dir: string, now: () => number = Date.now): Promise<AuthStore> {
    const file = path.join(dir, FILE_NAME);

    try {
      await fs.mkdir(dir, { recursive: true });
      // write probe: proves the directory accepts new files
      const probe = path.join(dir, `.write-probe-${process.pid}`);
      await fs.writeFile(probe, "");
      await fs.rm(probe, { force: true });
    } catch (err) {
      throw new Error(
        `Cannot use the data directory ${dir} for ${FILE_NAME}: ${(err as Error).message}`,
      );
    }

    let raw: string | undefined;
    try {
      raw = await fs.readFile(file, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code !== "ENOENT")
        throw new Error(`Cannot read ${file}: ${(err as Error).message}`);
    }

    let data: Data = { clients: new Map(), connections: new Map() };

    if (raw !== undefined) {
      let parsed: unknown;
      try {
        parsed = JSON.parse(raw);
      } catch {
        // the parser's message can quote the file, which holds tokens: never include it
        throw new Error(`${file} is not valid JSON`);
      }
      if (!isRecord(parsed) || !isRecord(parsed.clients) || !isRecord(parsed.connections))
        throw new Error(`${file} does not have the expected shape (clients and connections objects)`);
      data = {
        clients: new Map(Object.entries(parsed.clients)) as Data["clients"],
        connections: new Map(Object.entries(parsed.connections)) as Data["connections"],
      };
    }

    return new AuthStore(file, data, now);
  }

  getClient(id: string): OAuthClientInformationFull | undefined {
    return this.data.clients.get(id);
  }

  async saveClient(client: OAuthClientInformationFull): Promise<void> {
    this.data.clients.set(client.client_id, client);
    await this.persist();
  }

  async putConnection(c: Connection): Promise<Connection | undefined> {
    let replaced: Connection | undefined;

    for (const existing of [...this.data.connections.values()]) {
      if (existing.clientId === c.clientId && existing.person.id === c.person.id) {
        replaced = existing;
        this.data.connections.delete(existing.id);
      }
    }

    this.data.connections.set(c.id, c);
    await this.persist();
    return replaced;
  }

  findByRefresh(
    clientId: string,
    refreshToken: string,
  ): { connection: Connection; stale: boolean } | undefined {
    const hash = hashToken(refreshToken);

    for (const connection of this.data.connections.values()) {
      if (connection.clientId !== clientId)
        continue;

      if (connection.refreshHash === hash)
        return { connection, stale: false };

      if (
        connection.previousRefreshHash === hash &&
        connection.rotatedAt !== undefined &&
        this.now() - connection.rotatedAt <= REFRESH_GRACE_MS
      )
        return { connection, stale: true };
    }

    return undefined;
  }

  async updateConnection(c: Connection): Promise<void> {
    this.data.connections.set(c.id, c);
    await this.persist();
  }

  async removeConnection(id: string): Promise<Connection | undefined> {
    const existing = this.data.connections.get(id);

    if (!existing)
      return undefined;

    this.data.connections.delete(id);
    await this.persist();
    return existing;
  }

  expired(c: Connection): boolean {
    return this.now() - c.lastUsedAt > IDLE_EXPIRY_MS;
  }

  // writes are chained so two quick saves cannot interleave tmp-then-rename
  private persist(): Promise<void> {
    const run = this.writes.then(async () => {
      const tmp = `${this.file}.tmp`;
      await fs.writeFile(tmp, JSON.stringify(
        {
          clients: Object.fromEntries(this.data.clients),
          connections: Object.fromEntries(this.data.connections),
        },
        null,
        2,
      ), { mode: 0o600 });
      await fs.rename(tmp, this.file);
    });
    this.writes = run.catch(() => undefined);
    return run;
  }
}
