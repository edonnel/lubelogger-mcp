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
const ll = { ...base, PUBLIC_URL: "https://mcp.example.com" };

await check("lubelogger-password needs an allowlist of usernames", () => {
  const no = validateConfig({ ...ll, AUTH_METHODS: "lubelogger-password" });
  assert.ok(no.problems.some((p) => p.startsWith("LUBELOGGER_ALLOWED_USERS") && /lubelogger-password sign-in method/.test(p)));
  const yes = validateConfig({ ...ll, AUTH_METHODS: "lubelogger-password", LUBELOGGER_ALLOWED_USERS: " alice , bob " });
  assert.ok(yes.ok, JSON.stringify(yes.problems));
  assert.deepEqual(yes.config.LUBELOGGER_ALLOWED_USERS, ["alice", "bob"]);
});
await check("lubelogger-key alone needs no shared key; anything else still does", () => {
  const { LUBELOGGER_API_KEY, ...noKey } = ll;
  assert.ok(validateConfig({ ...noKey, AUTH_METHODS: "lubelogger-key" }).ok);
  const both = validateConfig({ ...noKey, AUTH_METHODS: "lubelogger-key,lubelogger-password", LUBELOGGER_ALLOWED_USERS: "alice" });
  assert.ok(both.problems.some((p) => p.startsWith("LUBELOGGER_API_KEY")));
  const token = validateConfig({ ...noKey, MCP_AUTH_TOKEN: "x".repeat(24) });
  assert.equal(token.ok, false);
  assert.ok(token.problems.some((p) => p.startsWith("LUBELOGGER_API_KEY")), JSON.stringify(token.problems));
});
await check("all four methods can be on together", () => {
  const r = validateConfig({ ...ha, ...oidc, AUTH_METHODS: "homeassistant,oidc,lubelogger-password,lubelogger-key", LUBELOGGER_ALLOWED_USERS: "alice" });
  assert.ok(r.ok, JSON.stringify(r.problems));
});
await check("no OIDC setting value appears in any problem", () => {
  const r = validateConfig({ ...oidc, OIDC_CLIENT_SECRET: "SECRET-PLANTED-31", OIDC_ISSUER: "not a url", AUTH_METHODS: "oidc" });
  assert.equal(r.ok, false);
  assert.ok(r.problems.every((p) => !p.includes("SECRET-PLANTED-31")));
});
await check("OIDC_AUTH_PARAMS may not set protocol parameters", () => {
  for (const name of ["client_id", "response_type", "response_mode", "request", "request_uri"]) {
    const r = validateConfig({ ...oidc, OIDC_AUTH_PARAMS: `${name}=x`, AUTH_METHODS: "oidc" });
    assert.equal(r.ok, false, name);
    assert.ok(r.problems.some((p) => p.includes("OIDC_AUTH_PARAMS") && p.includes(name)), `${name}: ${r.problems}`);
  }
  const ok = validateConfig({ ...oidc, OIDC_AUTH_PARAMS: "access_type=offline&prompt=consent", AUTH_METHODS: "oidc" });
  assert.ok(ok.ok, JSON.stringify(ok.problems));
});
await check("list settings are split on commas, trimmed, empties dropped", () => {
  const r = validateConfig({ ...oidc, OIDC_ALLOWED_EMAILS: " a@example.com, ,b@example.com,", AUTH_METHODS: "oidc" });
  assert.deepEqual(r.config.OIDC_ALLOWED_EMAILS, ["a@example.com", "b@example.com"]);
});
await check("the issuer is kept exactly as given, a trailing slash included", () => {
  // the provider's discovery document must name the same issuer, character for character
  const slash = validateConfig({ ...oidc, OIDC_ISSUER: "https://idp.example.com/application/o/mcp/", AUTH_METHODS: "oidc" });
  assert.ok(slash.ok, JSON.stringify(slash.problems));
  assert.equal(slash.config.OIDC_ISSUER, "https://idp.example.com/application/o/mcp/");
  const bare = validateConfig({ ...oidc, OIDC_ISSUER: "https://idp.example.com/realms/home", AUTH_METHODS: "oidc" });
  assert.equal(bare.config.OIDC_ISSUER, "https://idp.example.com/realms/home");
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

await check("the oidc checkbox adds oidc to AUTH_METHODS and passes its options", () => {
  const options = { ...addonOptions, oidc: true, oidc_issuer: "https://idp.example.com", oidc_client_id: "x", oidc_allowed_emails: "alice@example.com" };
  assert.deepEqual(check_options(options), []);
  const env = buildEnv(options);
  assert.equal(env.AUTH_METHODS, "homeassistant,oidc");
  assert.equal(env.OIDC_ISSUER, "https://idp.example.com");
  assert.ok(validateConfig(env).ok);
});

await check("oidc on without its settings names each one, never a value", () => {
  const problems = check_options({ ...addonOptions, oidc: true, oidc_client_secret: "SECRET-PLANTED-58" });
  for (const name of ["oidc_issuer", "oidc_client_id", "oidc_allowed_emails"]) assert.ok(problems.some((p) => p.includes(name)), name);
  assert.ok(problems.every((p) => !p.includes("SECRET-PLANTED-58")));
});

await check("oidc alone still requires public_url", () => {
  const options = { lubelogger_url: "http://lubelogger:8080", lubelogger_api_key: "k", homeassistant: false, oidc: true, oidc_issuer: "https://idp.example.com", oidc_client_id: "x", oidc_allowed_subjects: "s" };
  assert.ok(check_options(options).some((p) => /public_url/.test(p)));
});

await check("a switched-off oidc keeps its settings in the environment for cleanup", () => {
  const env = buildEnv({ ...addonOptions, oidc: false, oidc_issuer: "https://idp.example.com", oidc_client_id: "x" });
  assert.equal(env.AUTH_METHODS, "homeassistant");
  assert.equal(env.OIDC_ISSUER, "https://idp.example.com");
});

await check("the lubelogger_password and lubelogger_key checkboxes add their methods in order", () => {
  const options = { ...addonOptions, oidc: true, oidc_issuer: "https://idp.example.com", oidc_client_id: "x", oidc_allowed_emails: "alice@example.com", lubelogger_password: true, lubelogger_key: true, lubelogger_allowed_users: "alice" };
  assert.deepEqual(check_options(options), []);
  const env = buildEnv(options);
  assert.equal(env.AUTH_METHODS, "homeassistant,oidc,lubelogger-password,lubelogger-key");
  assert.equal(env.LUBELOGGER_ALLOWED_USERS, "alice");
  const r = validateConfig(env);
  assert.equal(r.ok, true, JSON.stringify(r.problems));
  // only exactly true switches them on
  assert.equal(buildEnv({ ...addonOptions, lubelogger_password: "true", lubelogger_key: 1 }).AUTH_METHODS, "homeassistant");
});

await check("lubelogger_password on without lubelogger_allowed_users names it", () => {
  const problems = check_options({ ...addonOptions, lubelogger_password: true });
  assert.ok(problems.some((p) => p.includes("lubelogger_allowed_users")));
  assert.ok(check_options({ ...addonOptions, lubelogger_password: true, lubelogger_allowed_users: "alice" }).length === 0);
  // not required while the method is off
  assert.deepEqual(check_options(addonOptions), []);
});

await check("lubelogger_key alone needs no lubelogger_api_key; anything else still does", () => {
  const key_only = { ...addonOptions, lubelogger_api_key: "", homeassistant: false, lubelogger_key: true };
  assert.deepEqual(check_options(key_only), []);
  const both = { ...key_only, homeassistant: true, lubelogger_api_key: "" };
  assert.ok(check_options(both).some((p) => p.includes("lubelogger_api_key")));
  const password_only = { ...addonOptions, lubelogger_api_key: "SECRET-PLANTED-91", homeassistant: false, lubelogger_password: true };
  assert.deepEqual(check_options(password_only), ["lubelogger_allowed_users is required while the lubelogger-password sign-in method is on"]);
  const missing = check_options({ ...password_only, lubelogger_api_key: undefined, lubelogger_allowed_users: "alice" });
  assert.ok(missing.some((p) => p.includes("lubelogger_api_key")));
  const planted = check_options({ ...both, lubelogger_api_key: "", lubelogger_allowed_users: "SECRET-PLANTED-91" });
  assert.ok(planted.every((p) => !p.includes("SECRET-PLANTED-91")));
});

if (failed) {
  console.error(`${failed} check(s) failed`);
  process.exit(1);
}
console.log("auth-config: all checks passed");
