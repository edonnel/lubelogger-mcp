// Builds the whole HTTP server for the configured sign-in methods, or token mode when there are none. index.ts only
// loads the config and listens; tests build it in-process with injected login methods and clock.
import { timingSafeEqual } from "node:crypto";
import express, { type NextFunction, type Request, type RequestHandler, type Response } from "express";
import type { AuthInfo } from "@modelcontextprotocol/sdk/server/auth/types.js";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { HomeAssistantLogin } from "./auth/homeassistant.js";
import type { AnyLoginMethod } from "./auth/login-method.js";
import { LubeLoggerKeyLogin, LubeLoggerPasswordLogin } from "./auth/lubelogger-login.js";
import { OidcLogin } from "./auth/oidc.js";
import { LoginProvider } from "./auth/provider.js";
import type { FailureLimiter } from "./auth/rate-limit.js";
import { mountOAuth, plainErrorPage } from "./auth/routes.js";
import { AuthStore } from "./auth/store.js";
import type { Config, MethodName } from "./config.js";
import { LubeLoggerClient } from "./lubelogger.js";
import { PendingStore } from "./pending.js";
import { registerRecordTools } from "./records.js";
import { registerReminderTools } from "./reminders.js";
import { registerTools } from "./tools.js";

const INSTRUCTIONS = [
  "Logs vehicle maintenance and fuel records into LubeLogger from documents you have read.",
  "Workflow: read the invoice/receipt/photo yourself, extract the fields, call the matching propose_* tool, show the preview to the user,",
  "and call commit_record only after they explicitly confirm.",
  "Odometer: use the document's reading if it has one, and never guess. Vehicles marked '(odometer optional)' in list_vehicles don't need one:",
  "suggest it once at most, don't insist, and leave it out if the user doesn't offer it (LubeLogger then shows the odometer blank).",
  "For other vehicles it is required: ask the user to type it or send a dashboard photo.",
  "If a vehicle is ambiguous, call list_vehicles and ask.",
  "Reminders (e.g. tire rotation) use the same propose/commit flow: check list_reminders first and prefer propose_reminder_update over a duplicate.",
  "Notes are Markdown laid out like the original document (facts as a list, line items as a table, totals as a list); the notes field spells out the format.",
  "To correct an existing record, find it with list_records (read it in full with get_record before rewriting notes), then call propose_record_update with only the fields that change",
  "(attachments and everything else are kept) and commit_record after the user confirms.",
].join(" ");

/** The endpoint in every OAuth mode; config refuses a custom MCP_PATH there. */
const OAUTH_ENDPOINT = "/mcp";

/**
 * `loginMethods` replaces the real implementation of any method it names, and `retiredMethods` that of any
 * switched-off method used for cleanup; tests inject stubs. `limiter` counts failed form sign-ins.
 */
export type AppDeps = {
  loginMethods?: Partial<Record<MethodName, AnyLoginMethod>>;
  retiredMethods?: Partial<Record<MethodName, AnyLoginMethod>>;
  now?: () => number;
  limiter?: FailureLimiter;
};

export async function createApp(
  config: Config,
  deps: AppDeps = {},
): Promise<{ app: express.Express; close(): Promise<void> }> {
  // the shared key's client; absent when lubelogger-key is the only method on
  const client = config.LUBELOGGER_API_KEY
    ? new LubeLoggerClient(config.LUBELOGGER_URL, config.LUBELOGGER_API_KEY, config.REQUEST_TIMEOUT_MS)
    : undefined;
  const pending = new PendingStore(config.CONFIRM_TTL_MINUTES * 60_000);

  /**
   * The LubeLogger client a verified request works with: an API-key connection's own key, built for this request
   * and never cached, and the shared key for every other connection.
   */
  function clientFor(auth?: AuthInfo): LubeLoggerClient {
    const key = auth?.extra?.lubeloggerKey;
    if (typeof key === "string" && key) return new LubeLoggerClient(config.LUBELOGGER_URL, key, config.REQUEST_TIMEOUT_MS);
    // an API-key connection must never fall back to the shared key, which can see more than the person can
    if (auth?.extra?.method === "lubelogger-key") throw new Error("this connection has no LubeLogger API key");
    if (!client) throw new Error("no shared LubeLogger API key is configured");
    return client;
  }

  function createServer(lubelogger: LubeLoggerClient): McpServer {
    const server = new McpServer({ name: "lubelogger-mcp", version: "0.1.0" }, { instructions: INSTRUCTIONS });
    const toolDeps = { client: lubelogger, pending, ttlMinutes: config.CONFIRM_TTL_MINUTES };
    registerTools(server, toolDeps);
    registerReminderTools(server, toolDeps);
    registerRecordTools(server, toolDeps);
    return server;
  }

  const app = express();
  app.disable("x-powered-by");

  app.get("/healthz", (_req, res) => {
    res.json({ status: "ok" });
  });

  // every mode decides its own guard for the endpoint; there is no unguarded default
  let endpoint: string;
  let guard: RequestHandler;
  let close = async (): Promise<void> => {};

  if (config.AUTH_METHODS.length === 0) {
    endpoint = config.MCP_PATH;
    guard = tokenGuard(config.MCP_AUTH_TOKEN);
  } else {
    const publicUrl = config.PUBLIC_URL;
    if (!publicUrl) throw new Error("PUBLIC_URL is required when a sign-in method is on");

    // in AUTH_METHODS order, which is the order of the buttons on the sign-in screen
    const methods = new Map<MethodName, AnyLoginMethod>();
    for (const name of config.AUTH_METHODS)
      methods.set(name, deps.loginMethods?.[name] ?? buildLoginMethod(name, config, publicUrl));

    // switched off but still configured: kept only to revoke the upstream sessions of their old connections
    const retired = buildRetiredMethods(config, publicUrl);
    for (const [name, method] of Object.entries(deps.retiredMethods ?? {}) as [MethodName, AnyLoginMethod][])
      if (!methods.has(name)) retired.set(name, method);

    // HA fetches its client ID (PUBLIC_URL + "/") to show the app's name and find its redirect URI
    const clientPage =
      "<!doctype html><html><head><meta charset=\"utf-8\"><title>LubeLogger MCP</title>" +
      `<link rel="redirect_uri" href="${escapeAttr(`${publicUrl}/login/callback`)}"></head>` +
      "<body><h1>LubeLogger MCP</h1><p>Connect from Claude to log vehicle maintenance into LubeLogger.</p></body></html>";
    app.get("/", (_req, res) => {
      res.type("html").send(clientPage);
    });

    const store = await AuthStore.open(config.DATA_DIR, deps.now);
    const provider = new LoginProvider(store, methods, deps.now, {
      allowedRedirectHosts: config.ALLOWED_REDIRECT_HOSTS,
      publicUrl,
      labels: { oidc: `Continue with ${config.OIDC_DISPLAY_NAME}` },
      retired,
      limiter: deps.limiter,
    });
    // connections unused for 90 days go now and hourly after, not only when one is presented again
    await provider.startPurging();
    endpoint = OAUTH_ENDPOINT;
    guard = mountOAuth(app, { publicUrl, provider });
    close = () => provider.close();
  }

  // Stateless Streamable HTTP: a fresh server + transport per request. Pending confirmations live in process memory, so they survive across requests.
  app.post(endpoint, guard, express.json({ limit: "1mb" }), async (req, res) => {
    let server: McpServer;
    try {
      server = createServer(clientFor(req.auth));
    } catch (err) {
      console.error("MCP request failed:", err instanceof Error ? err.message : err);
      res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
      return;
    }
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined });
    res.on("close", () => {
      void transport.close();
      void server.close();
    });
    try {
      await server.connect(transport);
      await transport.handleRequest(req, res, req.body);
    } catch (err) {
      console.error("MCP request failed:", err instanceof Error ? err.message : err);
      if (!res.headersSent) {
        res.status(500).json({ jsonrpc: "2.0", error: { code: -32603, message: "Internal server error" }, id: null });
      }
    }
  });

  const methodNotAllowed = (_req: Request, res: Response) => {
    res.status(405).json({ jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed (stateless server: use POST)." }, id: null });
  };
  app.get(endpoint, guard, methodNotAllowed);
  app.delete(endpoint, guard, methodNotAllowed);

  // sign-in serves browser pages, which must never show a stack trace; token mode is left as it was
  if (config.AUTH_METHODS.length > 0) app.use(plainErrorPage);

  return { app, close };
}

/** The real implementation of a sign-in method. Config has already refused any that is not available. */
function buildLoginMethod(name: MethodName, config: Config, publicUrl: string): AnyLoginMethod {
  if (name === "homeassistant") {
    if (!config.HOME_ASSISTANT_PUBLIC_URL || !config.HOME_ASSISTANT_URL)
      throw new Error("HOME_ASSISTANT_PUBLIC_URL and HOME_ASSISTANT_URL are required for the homeassistant sign-in method");
    return new HomeAssistantLogin({
      publicUrl,
      haPublicUrl: config.HOME_ASSISTANT_PUBLIC_URL,
      haUrl: config.HOME_ASSISTANT_URL,
    });
  }
  if (name === "oidc") {
    if (!config.OIDC_ISSUER || !config.OIDC_CLIENT_ID)
      throw new Error("OIDC_ISSUER and OIDC_CLIENT_ID are required for the oidc sign-in method");
    // discovery is lazy, so building this makes no network call
    return new OidcLogin({
      publicUrl,
      issuer: config.OIDC_ISSUER,
      clientId: config.OIDC_CLIENT_ID,
      clientSecret: config.OIDC_CLIENT_SECRET,
      allowedEmails: config.OIDC_ALLOWED_EMAILS,
      allowedSubjects: config.OIDC_ALLOWED_SUBJECTS,
      requiredGroup: config.OIDC_REQUIRED_GROUP,
      groupsClaim: config.OIDC_GROUPS_CLAIM,
      authParams: config.OIDC_AUTH_PARAMS,
    });
  }
  const lubelogger = { lubeloggerUrl: config.LUBELOGGER_URL, timeoutMs: config.REQUEST_TIMEOUT_MS };
  if (name === "lubelogger-password")
    return new LubeLoggerPasswordLogin({ ...lubelogger, allowedUsers: config.LUBELOGGER_ALLOWED_USERS });
  if (name === "lubelogger-key") return new LubeLoggerKeyLogin(lubelogger);
  throw new Error(`sign-in method ${name} is not available in this version`);
}

/** A method for each sign-in method that is off but still configured, so old connections' sessions can be revoked. */
function buildRetiredMethods(config: Config, publicUrl: string): Map<MethodName, AnyLoginMethod> {
  // the LubeLogger methods need only LUBELOGGER_URL, which is always set
  const configured: Record<MethodName, boolean> = {
    homeassistant: Boolean(config.HOME_ASSISTANT_URL && config.HOME_ASSISTANT_PUBLIC_URL),
    oidc: Boolean(config.OIDC_ISSUER && config.OIDC_CLIENT_ID),
    "lubelogger-password": true,
    "lubelogger-key": true,
  };
  const retired = new Map<MethodName, AnyLoginMethod>();
  for (const [name, isConfigured] of Object.entries(configured) as [MethodName, boolean][])
    if (isConfigured && !config.AUTH_METHODS.includes(name)) retired.set(name, buildLoginMethod(name, config, publicUrl));
  return retired;
}

function escapeAttr(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Token mode, unchanged: the bearer token when one is set; otherwise config has already required a secret MCP_PATH.
function tokenGuard(expected: string | undefined): RequestHandler {
  return (req: Request, res: Response, next: NextFunction): void => {
    if (!expected) return next();
    const header = req.headers.authorization ?? "";
    const given = header.startsWith("Bearer ") ? header.slice(7) : "";
    const a = Buffer.from(given);
    const b = Buffer.from(expected);
    if (a.length === b.length && timingSafeEqual(a, b)) return next();
    res.status(401).json({ jsonrpc: "2.0", error: { code: -32001, message: "Unauthorized" }, id: null });
  };
}
