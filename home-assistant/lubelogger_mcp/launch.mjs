// Home Assistant writes the add-on options to /data/options.json, which only root can read.
// Read them as root, then drop to the unprivileged node user before starting the server.
import { readFileSync } from "node:fs";

const options = JSON.parse(readFileSync("/data/options.json", "utf8"));

process.env.LUBELOGGER_URL = options.lubelogger_url;
process.env.LUBELOGGER_API_KEY = options.lubelogger_api_key;
process.env.MCP_PATH = options.mcp_path;

process.setgid("node");
process.setuid("node");
console.error(`lubelogger-mcp add-on: options loaded, running as uid ${process.getuid()}`);

await import("/app/dist/index.js");
