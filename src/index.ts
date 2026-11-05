import { createApp } from "./app.js";
import { loadConfig } from "./config.js";

const config = loadConfig();

let built: Awaited<ReturnType<typeof createApp>>;
try {
  built = await createApp(config);
} catch (err) {
  console.error(`Cannot start: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(1);
}

const httpServer = built.app.listen(config.PORT, config.HOST, () => {
  // MCP_PATH can be the only credential (clients that cannot send a bearer token), so a custom one is never logged
  const endpoint = config.MCP_PATH === "/mcp" ? "/mcp" : "a custom MCP_PATH (not shown)";
  // the sign-in methods decide the mode, whichever of AUTH_MODE or AUTH_METHODS set them
  const auth = config.AUTH_METHODS.length > 0 ? config.AUTH_METHODS.join(",") : "token";
  console.error(`lubelogger-mcp listening on http://${config.HOST}:${config.PORT}, endpoint ${endpoint}, auth ${auth}`);
  console.error(`LubeLogger: ${config.LUBELOGGER_URL}`);
});

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    httpServer.close(() => {
      void built.close().finally(() => process.exit(0));
    });
    setTimeout(() => process.exit(0), 3000).unref();
  });
}
