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

const ha = {
  ...base,
  PUBLIC_URL: "https://mcp.example.com",
  HOME_ASSISTANT_PUBLIC_URL: "https://ha.example.com",
  HOME_ASSISTANT_URL: "http://homeassistant:8123",
};

await check("AUTH_METHODS=homeassistant resolves to that list", () => {
  const r = validateConfig({ ...ha, AUTH_METHODS: "homeassistant" });
  assert.ok(r.ok, JSON.stringify(r.problems));
  assert.deepEqual(r.config.AUTH_METHODS, ["homeassistant"]);
});
await check("AUTH_METHODS trims spaces around names", () => {
  const r = validateConfig({ ...ha, AUTH_METHODS: " homeassistant " });
  assert.deepEqual(r.config.AUTH_METHODS, ["homeassistant"]);
});
await check("AUTH_MODE=homeassistant still works and means the same list", () => {
  const r = validateConfig({ ...ha, AUTH_MODE: "homeassistant" });
  assert.deepEqual(r.config.AUTH_METHODS, ["homeassistant"]);
});
await check("token mode has no methods", () => {
  const r = validateConfig({ ...base, MCP_AUTH_TOKEN: "x".repeat(24) });
  assert.deepEqual(r.config.AUTH_METHODS, []);
});
await check("AUTH_METHODS refuses unknown, duplicate and empty lists", () => {
  for (const [value, needle] of [
    ["homeassistant,nope", /nope/],
    ["homeassistant,homeassistant", /more than once/],
    [",", /at least one/],
  ]) {
    const r = validateConfig({ ...ha, AUTH_METHODS: value });
    assert.equal(r.ok, false);
    assert.ok(r.problems.some((p) => p.startsWith("AUTH_METHODS") && needle.test(p)), r.problems.join("\n"));
  }
});
await check("methods planned for later refuse to start", () => {
  const r = validateConfig({ ...ha, AUTH_METHODS: "homeassistant,oidc" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => /oidc.*not available in this version/.test(p)));
});
await check("AUTH_METHODS with a non-token AUTH_MODE refuses to start", () => {
  const r = validateConfig({ ...ha, AUTH_MODE: "homeassistant", AUTH_METHODS: "homeassistant" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => p.startsWith("AUTH_METHODS") && /AUTH_MODE/.test(p)));
});
await check("each method's settings are required only when it is on, and token conflicts still apply", () => {
  const r = validateConfig({ ...base, AUTH_METHODS: "homeassistant", PUBLIC_URL: "https://mcp.example.com" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => p.startsWith("HOME_ASSISTANT_PUBLIC_URL") && /homeassistant/.test(p)));
  const t = validateConfig({ ...ha, AUTH_METHODS: "homeassistant", MCP_AUTH_TOKEN: "x".repeat(24) });
  assert.ok(t.problems.some((p) => p.startsWith("MCP_AUTH_TOKEN")));
});

// the add-on launcher: importing it does not run it
const { buildEnv } = await import("../home-assistant/lubelogger_mcp/launch.mjs");
const addonOptions = {
  lubelogger_url: "http://local-lubelogger:8080",
  lubelogger_api_key: "key",
  public_url: "https://mcp.example.com",
  home_assistant_public_url: "https://ha.example.com",
};

check("the add-on leaves ALLOWED_REDIRECT_HOSTS to the default unless an option is set", () => {
  assert.equal(buildEnv(addonOptions).ALLOWED_REDIRECT_HOSTS, undefined);
  assert.equal(buildEnv({ ...addonOptions, allowed_redirect_hosts: "" }).ALLOWED_REDIRECT_HOSTS, undefined);
});

check("the add-on passes allowed_redirect_hosts through as ALLOWED_REDIRECT_HOSTS", () => {
  const env = buildEnv({ ...addonOptions, allowed_redirect_hosts: "claude.ai,claude.com,localhost,127.0.0.1" });
  assert.equal(env.ALLOWED_REDIRECT_HOSTS, "claude.ai,claude.com,localhost,127.0.0.1");
  const r = validateConfig(env);
  assert.equal(r.ok, true, JSON.stringify(r.problems));
  assert.deepEqual(r.config.ALLOWED_REDIRECT_HOSTS, ["claude.ai", "claude.com", "localhost", "127.0.0.1"]);
});

if (failed) {
  console.error(`${failed} check(s) failed`);
  process.exit(1);
}
console.log("auth-config: all checks passed");
