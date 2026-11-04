// Builds the whole HTTP server for the configured AUTH_MODE. index.ts only loads the config and listens;
// tests build it in-process with an injected login method and clock.
import { timingSafeEqual } from "node:crypto";
import express, { type NextFunction, type Request, type RequestHandler, type Response } from "express";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { HomeAssistantLogin } from "./auth/homeassistant.js";
import type { LoginMethod } from "./auth/login-method.js";
import { LoginProvider } from "./auth/provider.js";
import { mountOAuth, plainErrorPage } from "./auth/routes.js";
import { AuthStore } from "./auth/store.js";
import type { Config } from "./config.js";
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

export type AppDeps = { loginMethod?: LoginMethod; now?: () => number };

export async function createApp(
  config: Config,
  deps: AppDeps = {},
): Promise<{ app: express.Express; close(): Promise<void> }> {
  const client = new LubeLoggerClient(config.LUBELOGGER_URL, config.LUBELOGGER_API_KEY, config.REQUEST_TIMEOUT_MS);
  const pending = new PendingStore(config.CONFIRM_TTL_MINUTES * 60_000);

  function createServer(): McpServer {
    const server = new McpServer({ name: "lubelogger-mcp", version: "0.1.0" }, { instructions: INSTRUCTIONS });
    const toolDeps = { client, pending, ttlMinutes: config.CONFIRM_TTL_MINUTES };
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

  if (config.AUTH_MODE === "token") {
    endpoint = config.MCP_PATH;
    guard = tokenGuard(config.MCP_AUTH_TOKEN);
  } else if (config.AUTH_MODE === "homeassistant") {
    const publicUrl = config.PUBLIC_URL;
    if (!publicUrl) throw new Error("PUBLIC_URL is required when AUTH_MODE is homeassistant");
    if (!config.HOME_ASSISTANT_PUBLIC_URL || !config.HOME_ASSISTANT_URL)
      throw new Error("HOME_ASSISTANT_PUBLIC_URL and HOME_ASSISTANT_URL are required when AUTH_MODE is homeassistant");
    const method =
      deps.loginMethod ??
      new HomeAssistantLogin({
        publicUrl,
        haPublicUrl: config.HOME_ASSISTANT_PUBLIC_URL,
        haUrl: config.HOME_ASSISTANT_URL,
      });

    // HA fetches its client ID (PUBLIC_URL + "/") to show the app's name and find its redirect URI
    const clientPage =
      "<!doctype html><html><head><meta charset=\"utf-8\"><title>LubeLogger MCP</title>" +
      `<link rel="redirect_uri" href="${escapeAttr(`${publicUrl}/login/callback`)}"></head>` +
      "<body><h1>LubeLogger MCP</h1><p>Connect from Claude to log vehicle maintenance into LubeLogger.</p></body></html>";
    app.get("/", (_req, res) => {
      res.type("html").send(clientPage);
    });

    const store = await AuthStore.open(config.DATA_DIR, deps.now);
    const provider = new LoginProvider(store, method, deps.now, {
      allowedRedirectHosts: config.ALLOWED_REDIRECT_HOSTS,
      publicUrl,
    });
    endpoint = OAUTH_ENDPOINT;
    guard = mountOAuth(app, { publicUrl, provider });
    close = () => provider.close();
  } else {
    throw new Error(`AUTH_MODE ${String(config.AUTH_MODE)} is not available in this version`);
  }

  // Stateless Streamable HTTP: a fresh server + transport per request. Pending confirmations live in process memory, so they survive across requests.
  app.post(endpoint, guard, express.json({ limit: "1mb" }), async (req, res) => {
    const server = createServer();
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

  // OAuth modes serve browser pages, which must never show a stack trace; token mode is left as it was
  if (config.AUTH_MODE !== "token") app.use(plainErrorPage);

  return { app, close };
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
