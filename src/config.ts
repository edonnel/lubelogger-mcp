import { z } from "zod";

const schema = z.object({
  LUBELOGGER_URL: z
    .string()
    .url("must be a full URL, e.g. http://lubelogger:8080")
    .transform((v) => v.replace(/\/+$/, "")),
  /** Required unless lubelogger-key is the only sign-in method on (checked below). */
  LUBELOGGER_API_KEY: z.string().min(1).optional(),
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

/** Every sign-in method the server knows by name. */
export const METHOD_NAMES = ["homeassistant", "oidc", "lubelogger-password", "lubelogger-key"] as const;
export type MethodName = (typeof METHOD_NAMES)[number];

/** This version implements these methods; the rest are accepted by the schema but refuse to start. */
const AVAILABLE_METHODS: readonly MethodName[] = ["homeassistant", "oidc", "lubelogger-password", "lubelogger-key"];

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

/** Comma-separated list setting: split, trimmed, empty entries dropped. */
const commaList = z
  .string()
  .default("")
  .transform((v) => v.split(",").map((e) => e.trim()).filter((e) => e !== ""));

/**
 * An OpenID Connect issuer, kept exactly as given: discovery compares it to the provider's own issuer character for
 * character, so a trailing slash is part of the identifier. A path is allowed; https only (plain http on localhost for testing).
 */
const issuerUrl = z
  .string()
  .url("must be a full URL, e.g. https://idp.example.com/realms/home")
  .refine((v) => {
    // with no transform in between, this runs after a failed url check too; that check already reports it
    let u: URL;
    try {
      u = new URL(v);
    } catch {
      return true;
    }
    return u.protocol === "https:" || (u.protocol === "http:" && (u.hostname === "localhost" || u.hostname === "127.0.0.1"));
  }, "must use https (http is accepted only for localhost or 127.0.0.1)");

const authSchema = z.object({
  AUTH_MODE: z.enum(["token", "homeassistant", "oidc", "lubelogger-key", "lubelogger-password"]).default("token"),
  /** Sign-in methods to offer, comma-separated, in order. Mutually exclusive with a non-token AUTH_MODE. */
  AUTH_METHODS: z.string().optional(),
  /** Public address of this server, as clients reach it. Needed when a sign-in method is on. */
  PUBLIC_URL: originUrl("https://mcp.example.com").optional(),
  /** Public address of Home Assistant, where the browser is sent to sign in. */
  HOME_ASSISTANT_PUBLIC_URL: originUrl("https://homeassistant.example.com").optional(),
  /** Address of Home Assistant as this server reaches it, e.g. http://homeassistant:8123. */
  HOME_ASSISTANT_URL: originUrl("http://homeassistant:8123").optional(),
  /** OpenID Connect: the issuer's address, the client registered for this server, and an optional client secret. */
  OIDC_ISSUER: issuerUrl.optional(),
  OIDC_CLIENT_ID: z.string().min(1).optional(),
  OIDC_CLIENT_SECRET: z.string().min(1).optional(),
  /** Name shown on the sign-in button. */
  OIDC_DISPLAY_NAME: z.string().min(1).default("single sign-on"),
  /** Who may sign in: any listed email or subject, or members of the required group. */
  OIDC_ALLOWED_EMAILS: commaList,
  OIDC_ALLOWED_SUBJECTS: commaList,
  OIDC_REQUIRED_GROUP: z.string().min(1).optional(),
  /** LubeLogger usernames allowed to sign in with the lubelogger-password method. */
  LUBELOGGER_ALLOWED_USERS: commaList,
  OIDC_GROUPS_CLAIM: z.string().min(1).default("groups"),
  /** Extra query parameters for the authorization request, passed through as given. */
  OIDC_AUTH_PARAMS: z.string().min(1).optional(),
  /** Where OAuth state is kept. */
  DATA_DIR: z.string().default("./data"),
  /** Hostnames an OAuth client may register as its redirect target, comma-separated. */
  ALLOWED_REDIRECT_HOSTS: z
    .string()
    .default("claude.ai,claude.com")
    .transform((v) => v.split(",").map((h) => h.trim().toLowerCase()).filter((h) => h !== ""))
    .refine((hosts) => hosts.length > 0, "must list at least one hostname"),
});

const fullSchema = schema.extend(authSchema.shape);

const OAUTH_ENDPOINT = "/mcp";

type ResolveInput = { AUTH_MODE: string; AUTH_METHODS?: string | undefined };

/**
 * The sign-in methods the settings ask for. A non-token AUTH_MODE alone means just that method; AUTH_METHODS alone
 * is its list; neither means token mode (no methods). Problems are reported on the setting the list came from.
 */
function resolveMethods(c: ResolveInput): { methods: MethodName[]; problems: { path: string; message: string }[] } {
  const problems: { path: string; message: string }[] = [];

  if (c.AUTH_MODE !== "token" && c.AUTH_METHODS !== undefined) {
    problems.push({
      path: "AUTH_METHODS",
      message: `must not be set together with AUTH_MODE=${c.AUTH_MODE} (use one or the other)`,
    });
    return { methods: [], problems };
  }

  const source = c.AUTH_MODE !== "token" ? "AUTH_MODE" : "AUTH_METHODS";
  const names =
    c.AUTH_MODE !== "token"
      ? [c.AUTH_MODE]
      : c.AUTH_METHODS === undefined
        ? []
        : c.AUTH_METHODS.split(",").map((n) => n.trim()).filter((n) => n !== "");

  if (source === "AUTH_METHODS" && c.AUTH_METHODS !== undefined && names.length === 0) {
    problems.push({ path: source, message: "must list at least one sign-in method" });
    return { methods: [], problems };
  }

  const choices = ["token", ...AVAILABLE_METHODS];
  const modeChoices = `${choices.slice(0, -1).join(", ")} or ${choices[choices.length - 1]}`;
  const methods: MethodName[] = [];
  const seen = new Set<string>();
  for (const name of names) {
    if (!(METHOD_NAMES as readonly string[]).includes(name)) {
      problems.push({
        path: source,
        message: `"${name}" is not a sign-in method (use one of ${METHOD_NAMES.join(", ")})`,
      });
      continue;
    }
    if (seen.has(name)) {
      if (!problems.some((p) => p.message === `lists "${name}" more than once`))
        problems.push({ path: source, message: `lists "${name}" more than once` });
      continue;
    }
    seen.add(name);
    if (!AVAILABLE_METHODS.includes(name as MethodName)) {
      problems.push({
        path: source,
        message:
          source === "AUTH_MODE"
            ? `"${name}" is not available in this version (use ${modeChoices})`
            : `"${name}" is not available in this version (use ${AVAILABLE_METHODS.join(", ")})`,
      });
      continue;
    }
    methods.push(name as MethodName);
  }
  return { methods, problems };
}

// No methods (token mode): without a bearer token the path is the only credential, so refuse to serve an endpoint anyone could find.
// With methods: the endpoint is fixed and the sign-in is the credential.
const checkedSchema = fullSchema
  .superRefine((c, ctx) => {
    const { methods, problems } = resolveMethods(c);
    if (problems.length > 0) {
      for (const p of problems) ctx.addIssue({ code: "custom", path: [p.path], message: p.message });
      return;
    }

    // the shared key is needed in token mode and by every method except lubelogger-key (which signs in with each person's own key)
    if (c.LUBELOGGER_API_KEY === undefined && !(methods.length === 1 && methods[0] === "lubelogger-key"))
      ctx.addIssue({
        code: "custom",
        path: ["LUBELOGGER_API_KEY"],
        message: "is required (create one in LubeLogger, Editor role is enough)",
      });

    if (methods.length === 0) {
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

    if (c.MCP_AUTH_TOKEN !== undefined)
      ctx.addIssue({
        code: "custom",
        path: ["MCP_AUTH_TOKEN"],
        message: "must not be set when a sign-in method is on (sign-in replaces the bearer token)",
      });

    if (c.MCP_PATH !== OAUTH_ENDPOINT)
      ctx.addIssue({
        code: "custom",
        path: ["MCP_PATH"],
        message: `must not be set when a sign-in method is on (the endpoint is fixed at ${OAUTH_ENDPOINT})`,
      });

    if (c.PUBLIC_URL === undefined)
      ctx.addIssue({ code: "custom", path: ["PUBLIC_URL"], message: "is required when a sign-in method is on" });

    if (methods.includes("homeassistant"))
      for (const name of ["HOME_ASSISTANT_PUBLIC_URL", "HOME_ASSISTANT_URL"] as const)
        if (c[name] === undefined)
          ctx.addIssue({
            code: "custom",
            path: [name],
            message: "is required when the homeassistant sign-in method is on",
          });

    if (methods.includes("lubelogger-password") && c.LUBELOGGER_ALLOWED_USERS.length === 0)
      ctx.addIssue({
        code: "custom",
        path: ["LUBELOGGER_ALLOWED_USERS"],
        message: "is required when the lubelogger-password sign-in method is on",
      });

    if (methods.includes("oidc")) {
      for (const name of ["OIDC_ISSUER", "OIDC_CLIENT_ID"] as const)
        if (c[name] === undefined)
          ctx.addIssue({ code: "custom", path: [name], message: "is required when the oidc sign-in method is on" });

      if (c.OIDC_ALLOWED_EMAILS.length === 0 && c.OIDC_ALLOWED_SUBJECTS.length === 0 && c.OIDC_REQUIRED_GROUP === undefined)
        ctx.addIssue({
          code: "custom",
          path: ["OIDC_ALLOWED_EMAILS"],
          message:
            "at least one of OIDC_ALLOWED_EMAILS, OIDC_ALLOWED_SUBJECTS or OIDC_REQUIRED_GROUP is required when the oidc sign-in method is on",
        });
    }
  })
  .transform((c) => ({ ...c, AUTH_METHODS: resolveMethods(c).methods }));

export type Config = z.output<typeof checkedSchema>;

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
