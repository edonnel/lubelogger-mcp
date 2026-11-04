// Config rules for the auth modes. Uses the built output in dist/.
import assert from "node:assert/strict";
import { validateConfig } from "../dist/config.js";

const base = {
  LUBELOGGER_URL: "http://lubelogger:8080",
  LUBELOGGER_API_KEY: "test-api-key",
};
const haEnv = {
  ...base,
  AUTH_MODE: "homeassistant",
  PUBLIC_URL: "https://mcp.example.com",
  HOME_ASSISTANT_PUBLIC_URL: "https://ha.example.com",
  HOME_ASSISTANT_URL: "http://homeassistant:8123",
};

let failed = 0;
function check(name, fn) {
  try {
    fn();
    console.log(`ok - ${name}`);
  } catch (err) {
    failed++;
    console.error(`FAIL - ${name}\n${err.stack}`);
  }
}

check("token mode with a bearer token is valid", () => {
  const r = validateConfig({ ...base, MCP_AUTH_TOKEN: "test-token-0123456789abcdef" });
  assert.equal(r.ok, true);
  assert.equal(r.config.AUTH_MODE, "token");
  assert.equal(r.config.DATA_DIR, "./data");
});

check("homeassistant mode needs PUBLIC_URL, HOME_ASSISTANT_PUBLIC_URL and HOME_ASSISTANT_URL", () => {
  const r = validateConfig({ ...base, AUTH_MODE: "homeassistant" });
  assert.equal(r.ok, false);
  assert.equal(r.problems.length, 3);
  for (const name of ["PUBLIC_URL", "HOME_ASSISTANT_PUBLIC_URL", "HOME_ASSISTANT_URL"])
    assert.ok(
      r.problems.some((p) => p.startsWith(`${name}:`)),
      `no problem names ${name}`,
    );
});

check("homeassistant mode refuses MCP_AUTH_TOKEN", () => {
  const r = validateConfig({ ...haEnv, MCP_AUTH_TOKEN: "test-token-0123456789abcdef" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => /MCP_AUTH_TOKEN/.test(p)));
});

check("homeassistant mode refuses a custom MCP_PATH", () => {
  const r = validateConfig({ ...haEnv, MCP_PATH: "/mcp/custom" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => /MCP_PATH/.test(p)));
});

check("homeassistant mode does not need a secret path", () => {
  const r = validateConfig(haEnv);
  assert.equal(r.ok, true, r.problems?.join("; "));
  assert.equal(r.config.AUTH_MODE, "homeassistant");
  assert.equal(r.config.MCP_PATH, "/mcp");
});

check("trailing slashes are trimmed", () => {
  const r = validateConfig({
    ...haEnv,
    PUBLIC_URL: "https://mcp.example.com/",
    HOME_ASSISTANT_PUBLIC_URL: "https://ha.example.com//",
    HOME_ASSISTANT_URL: "http://homeassistant:8123/",
  });
  assert.equal(r.ok, true, r.problems?.join("; "));
  assert.equal(r.config.PUBLIC_URL, "https://mcp.example.com");
  assert.equal(r.config.HOME_ASSISTANT_PUBLIC_URL, "https://ha.example.com");
  assert.equal(r.config.HOME_ASSISTANT_URL, "http://homeassistant:8123");
});

check("a path in PUBLIC_URL is refused", () => {
  const r = validateConfig({ ...haEnv, PUBLIC_URL: "https://mcp.example.com/mcp" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => /PUBLIC_URL/.test(p)));
});

check("a path in HOME_ASSISTANT_PUBLIC_URL is refused", () => {
  const r = validateConfig({ ...haEnv, HOME_ASSISTANT_PUBLIC_URL: "https://ha.example.com/lovelace" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => /HOME_ASSISTANT_PUBLIC_URL/.test(p)));
});

check("ALLOWED_REDIRECT_HOSTS defaults to claude.ai and claude.com", () => {
  const r = validateConfig(haEnv);
  assert.equal(r.ok, true);
  assert.deepEqual(r.config.ALLOWED_REDIRECT_HOSTS, ["claude.ai", "claude.com"]);
});

check("ALLOWED_REDIRECT_HOSTS is split, trimmed and lower-cased", () => {
  const r = validateConfig({ ...haEnv, ALLOWED_REDIRECT_HOSTS: " Claude.AI, localhost ,,app.example.com " });
  assert.equal(r.ok, true);
  assert.deepEqual(r.config.ALLOWED_REDIRECT_HOSTS, ["claude.ai", "localhost", "app.example.com"]);
});

check("oidc is not available in this version", () => {
  const r = validateConfig({ ...base, AUTH_MODE: "oidc" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => /not available in this version/.test(p)));
});

if (failed) {
  console.error(`${failed} check(s) failed`);
  process.exit(1);
}
console.log("auth-config: all checks passed");
