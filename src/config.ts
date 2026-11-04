import { z } from "zod";

const schema = z.object({
  LUBELOGGER_URL: z
    .string()
    .url("must be a full URL, e.g. http://lubelogger:8080")
    .transform((v) => v.replace(/\/+$/, "")),
  LUBELOGGER_API_KEY: z.string().min(1, "is required (create one in LubeLogger, Editor role is enough)"),
  /** Optional bearer token required on the MCP endpoint. */
  MCP_AUTH_TOKEN: z.string().min(16, "should be at least 16 characters").optional(),
  /** Endpoint path. Use a long random path (e.g. /mcp/<random>) if you expose this publicly without a bearer token. */
  MCP_PATH: z
    .string()
    .default("/mcp")
    .refine((p) => p.startsWith("/"), "must start with /"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  HOST: z.string().default("0.0.0.0"),
  CONFIRM_TTL_MINUTES: z.coerce.number().positive().default(30),
  REQUEST_TIMEOUT_MS: z.coerce.number().positive().default(15_000),
});

/** Shortest path segment accepted as a secret when there is no bearer token: 32 hex characters is 128 bits. */
const MIN_SECRET_SEGMENT = 32;

/** Release 1 implements these modes; the rest are accepted by the schema but refuse to start. */
const AVAILABLE_MODES = ["token", "homeassistant"];

/** A bare origin: trailing slashes are trimmed and any path, query or fragment is refused. */
const originUrl = (example: string) =>
  z
    .string()
    .url(`must be a full URL, e.g. ${example}`)
    .transform((v) => v.replace(/\/+$/, ""))
    .refine((v) => {
      const u = new URL(v);
      return u.pathname === "/" && !u.search && !u.hash;
    }, `must be an address only, with no path (e.g. ${example})`);

const authSchema = z.object({
  AUTH_MODE: z.enum(["token", "homeassistant", "oidc", "lubelogger-key", "lubelogger-password"]).default("token"),
  /** Public address of this server, as clients reach it. Needed in OAuth modes. */
  PUBLIC_URL: originUrl("https://mcp.example.com").optional(),
  /** Public address of Home Assistant, where the browser is sent to sign in. */
  HOME_ASSISTANT_PUBLIC_URL: originUrl("https://homeassistant.example.com").optional(),
  /** Address of Home Assistant as this server reaches it, e.g. http://homeassistant:8123. */
  HOME_ASSISTANT_URL: originUrl("http://homeassistant:8123").optional(),
  /** Where OAuth state is kept. */
  DATA_DIR: z.string().default("./data"),
});

const fullSchema = schema.extend(authSchema.shape);

const OAUTH_ENDPOINT = "/mcp";

// Token mode: without a bearer token the path is the only credential, so refuse to serve an endpoint anyone could find.
// OAuth modes: the endpoint is fixed and the sign-in is the credential.
const checkedSchema = fullSchema.superRefine((c, ctx) => {
  if (!AVAILABLE_MODES.includes(c.AUTH_MODE)) {
    ctx.addIssue({
      code: "custom",
      path: ["AUTH_MODE"],
      message: `"${c.AUTH_MODE}" is not available in this version (use token or homeassistant)`,
    });
    return;
  }

  if (c.AUTH_MODE === "token") {
    if (c.MCP_AUTH_TOKEN === undefined && !c.MCP_PATH.split("/").some((s) => s.length >= MIN_SECRET_SEGMENT))
      ctx.addIssue({
        code: "custom",
        path: ["MCP_PATH"],
        message:
          `needs a random segment of at least ${MIN_SECRET_SEGMENT} characters when MCP_AUTH_TOKEN is not set ` +
          "(e.g. /mcp/<output of: openssl rand -hex 16>). Otherwise anyone who can reach the port can write to LubeLogger.",
      });
    return;
  }

  // homeassistant
  if (c.MCP_AUTH_TOKEN !== undefined)
    ctx.addIssue({
      code: "custom",
      path: ["MCP_AUTH_TOKEN"],
      message: `must not be set when AUTH_MODE is ${c.AUTH_MODE} (sign-in replaces the bearer token)`,
    });

  if (c.MCP_PATH !== OAUTH_ENDPOINT)
    ctx.addIssue({
      code: "custom",
      path: ["MCP_PATH"],
      message: `must not be set when AUTH_MODE is ${c.AUTH_MODE} (the endpoint is fixed at ${OAUTH_ENDPOINT})`,
    });

  for (const name of ["PUBLIC_URL", "HOME_ASSISTANT_PUBLIC_URL", "HOME_ASSISTANT_URL"] as const)
    if (c[name] === undefined)
      ctx.addIssue({ code: "custom", path: [name], message: `is required when AUTH_MODE is ${c.AUTH_MODE}` });
});

export type Config = z.infer<typeof fullSchema>;

export type ConfigResult = { ok: true; config: Config } | { ok: false; problems: string[] };

export function validateConfig(env: NodeJS.ProcessEnv = process.env): ConfigResult {
  // Treat empty strings (common with docker compose ${VAR:-}) as unset.
  const cleaned = Object.fromEntries(Object.entries(env).filter(([, v]) => v !== undefined && v !== ""));
  const parsed = checkedSchema.safeParse(cleaned);
  if (!parsed.success)
    return {
      ok: false,
      problems: parsed.error.issues.map((i) => `${i.path.join(".") || "(env)"}: ${i.message}`),
    };
  return { ok: true, config: parsed.data };
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const result = validateConfig(env);
  if (!result.ok) {
    console.error(`Invalid configuration:\n${result.problems.map((p) => `  - ${p}`).join("\n")}`);
    process.exit(1);
  }
  return result.config;
}
