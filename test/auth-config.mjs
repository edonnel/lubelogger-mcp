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
const oidc = {
  ...base,
  PUBLIC_URL: "https://mcp.example.com",
  OIDC_ISSUER: "https://idp.example.com/realms/home",
  OIDC_CLIENT_ID: "lubelogger-mcp",
  OIDC_ALLOWED_EMAILS: "alice@example.com",
};

await check("AUTH_METHODS=oidc with an issuer, client and allowlist starts", () => {
  const r = validateConfig({ ...oidc, AUTH_METHODS: "oidc" });
  assert.ok(r.ok, JSON.stringify(r.problems));
  assert.deepEqual(r.config.AUTH_METHODS, ["oidc"]);
  assert.deepEqual(r.config.OIDC_ALLOWED_EMAILS, ["alice@example.com"]);
  assert.equal(r.config.OIDC_DISPLAY_NAME, "single sign-on");
  assert.equal(r.config.OIDC_GROUPS_CLAIM, "groups");
});
await check("both methods together start, in the order given", () => {
  const r = validateConfig({ ...ha, ...oidc, AUTH_METHODS: "oidc,homeassistant" });
  assert.deepEqual(r.config.AUTH_METHODS, ["oidc", "homeassistant"]);
});
await check("oidc without an allowlist refuses to start", () => {
  const r = validateConfig({ ...oidc, OIDC_ALLOWED_EMAILS: undefined, AUTH_METHODS: "oidc" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => /OIDC_ALLOWED_EMAILS, OIDC_ALLOWED_SUBJECTS or OIDC_REQUIRED_GROUP/.test(p)));
});
await check("oidc names each missing setting", () => {
  const r = validateConfig({ ...base, PUBLIC_URL: "https://mcp.example.com", OIDC_ALLOWED_SUBJECTS: "abc", AUTH_METHODS: "oidc" });
  for (const name of ["OIDC_ISSUER", "OIDC_CLIENT_ID"])
    assert.ok(r.problems.some((p) => p.startsWith(name) && /oidc sign-in method/.test(p)), name);
});
await check("an issuer must be https, except on localhost", () => {
  assert.equal(validateConfig({ ...oidc, OIDC_ISSUER: "http://idp.example.com", AUTH_METHODS: "oidc" }).ok, false);
  assert.ok(validateConfig({ ...oidc, OIDC_ISSUER: "http://localhost:9000/realms/home", AUTH_METHODS: "oidc" }).ok);
  assert.ok(validateConfig({ ...oidc, OIDC_ISSUER: "http://127.0.0.1:9000", AUTH_METHODS: "oidc" }).ok);
});
await check("lubelogger methods still refuse to start", () => {
  const r = validateConfig({ ...ha, AUTH_METHODS: "homeassistant,lubelogger-key" });
  assert.ok(r.problems.some((p) => /lubelogger-key.*not available in this version/.test(p)));
});
await check("no OIDC setting value appears in any problem", () => {
  const r = validateConfig({ ...oidc, OIDC_CLIENT_SECRET: "SECRET-PLANTED-31", OIDC_ISSUER: "not a url", AUTH_METHODS: "oidc" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.every((p) => !p.includes("SECRET-PLANTED-31")));
});
await check("list settings are split on commas, trimmed, empties dropped; issuer slashes trimmed", () => {
  const r = validateConfig({ ...oidc, OIDC_ALLOWED_EMAILS: " a@example.com, ,b@example.com,", OIDC_ISSUER: "https://idp.example.com/realms/home//", AUTH_METHODS: "oidc" });
  assert.deepEqual(r.config.OIDC_ALLOWED_EMAILS, ["a@example.com", "b@example.com"]);
  assert.equal(r.config.OIDC_ISSUER, "https://idp.example.com/realms/home");
});
await check("a required group alone satisfies the allowlist", () => {
  const r = validateConfig({ ...oidc, OIDC_ALLOWED_EMAILS: undefined, OIDC_REQUIRED_GROUP: "mcp", AUTH_METHODS: "oidc" });
  assert.ok(r.ok, JSON.stringify(r.problems));
});
await check("oidc settings are format-checked when oidc is off, and never required", () => {
  assert.ok(validateConfig({ ...ha, AUTH_METHODS: "homeassistant" }).ok);
  const r = validateConfig({ ...ha, AUTH_METHODS: "homeassistant", OIDC_ISSUER: "http://idp.example.com" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.some((p) => p.startsWith("OIDC_ISSUER")));
});
await check("AUTH_MODE=oidc is accepted", () => {
  assert.ok(validateConfig({ ...oidc, AUTH_MODE: "oidc" }).ok);
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
const { buildEnv, check_options } = await import("../home-assistant/lubelogger_mcp/launch.mjs");
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

await check("0.4 options without a homeassistant key start in Home Assistant mode", () => {
  const env = buildEnv(addonOptions);
  assert.equal(env.AUTH_METHODS, "homeassistant");
  assert.equal(env.AUTH_MODE, undefined);
  assert.deepEqual(check_options(addonOptions), []);
  assert.ok(validateConfig(env).ok);
});

await check("homeassistant: false with nothing else on is refused by the launcher", () => {
  const problems = check_options({ ...addonOptions, homeassistant: false });
  assert.equal(problems.length, 1);
  assert.match(problems[0], /at least one sign-in method/);
});

await check("a missing URL is named, and no option value appears in any message", () => {
  const options = { ...addonOptions, lubelogger_api_key: "SECRET-PLANTED-77", public_url: "" };
  const problems = check_options(options);
  assert.ok(problems.some((p) => /public_url/.test(p)));
  assert.ok(problems.every((p) => !p.includes("SECRET-PLANTED-77")));
  assert.ok(check_options({ ...addonOptions, home_assistant_public_url: undefined }).some((p) => /home_assistant_public_url/.test(p)));
});

if (failed) {
  console.error(`${failed} check(s) failed`);
  process.exit(1);
}
console.log("auth-config: all checks passed");
