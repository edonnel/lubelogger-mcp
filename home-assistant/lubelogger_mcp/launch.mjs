// Home Assistant writes the add-on options to /data/options.json, which only root can read.
// Read them as root, prepare the state folder, then drop to the unprivileged node user before starting the server.
import { chmodSync, lchownSync, lstatSync, mkdirSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const STATE_DIR = "/data/oauth";

/** True for an option that holds text. */
function is_set(value) {
	return typeof value === "string" && value !== "";
}

/**
 * The sign-in methods that are switched on. The homeassistant checkbox is on unless its option is exactly false, so 0.4
 * options keep working. The oidc, lubelogger_password and lubelogger_key checkboxes are the other way round: each is on
 * only when exactly true.
 */
function enabled_methods(options) {
	const methods = [];

	if (options.homeassistant !== false)
		methods.push("homeassistant");

	if (options.oidc === true)
		methods.push("oidc");

	if (options.lubelogger_password === true)
		methods.push("lubelogger-password");

	if (options.lubelogger_key === true)
		methods.push("lubelogger-key");

	return methods;
}

/** Problems with the add-on options, as messages that name options and never contain their values. */
export function check_options(options) {
	const methods = enabled_methods(options);

	if (methods.length === 0)
		return ["switch on at least one sign-in method"];

	const problems = [];

	if (!is_set(options.public_url))
		problems.push("public_url is required while a sign-in method is on");

	if (methods.includes("homeassistant") && !is_set(options.home_assistant_public_url))
		problems.push("home_assistant_public_url is required while the homeassistant sign-in method is on");

	if (methods.includes("oidc")) {
		for (const name of ["oidc_issuer", "oidc_client_id"]) {
			if (!is_set(options[name]))
				problems.push(`${name} is required while the oidc sign-in method is on`);
		}

		const allowlists = ["oidc_allowed_emails", "oidc_allowed_subjects", "oidc_required_group"];

		if (!allowlists.some((name) => is_set(options[name])))
			problems.push(`set at least one of ${allowlists.join(", ")} while the oidc sign-in method is on`);
	}

	if (methods.includes("lubelogger-password") && !is_set(options.lubelogger_allowed_users))
		problems.push("lubelogger_allowed_users is required while the lubelogger-password sign-in method is on");

	// the key alone signs in with the key the person types, so the stored one is optional only then
	const key_only = methods.length === 1 && methods[0] === "lubelogger-key";

	if (!key_only && !is_set(options.lubelogger_api_key))
		problems.push("lubelogger_api_key is required unless lubelogger-key is the only sign-in method on");

	return problems;
}

/** Builds the server's environment from the add-on options. A leftover mcp_path from older installs is ignored. */
export function buildEnv(options) {
	const env = {
		LUBELOGGER_URL: options.lubelogger_url,
		LUBELOGGER_API_KEY: options.lubelogger_api_key,
		LUBELOGGER_ALLOWED_USERS: options.lubelogger_allowed_users,
		AUTH_METHODS: enabled_methods(options).join(","),
		HOME_ASSISTANT_URL: "http://homeassistant:8123",
		DATA_DIR: STATE_DIR,
		PUBLIC_URL: options.public_url,
		HOME_ASSISTANT_PUBLIC_URL: options.home_assistant_public_url,
		// optional: without it the server allows only Claude's own return addresses
		ALLOWED_REDIRECT_HOSTS: options.allowed_redirect_hosts,
		// passed even while oidc is off: the server format-checks them and uses them to clean up a switched-off method
		OIDC_ISSUER: options.oidc_issuer,
		OIDC_CLIENT_ID: options.oidc_client_id,
		OIDC_CLIENT_SECRET: options.oidc_client_secret,
		OIDC_DISPLAY_NAME: options.oidc_display_name,
		OIDC_ALLOWED_EMAILS: options.oidc_allowed_emails,
		OIDC_ALLOWED_SUBJECTS: options.oidc_allowed_subjects,
		OIDC_REQUIRED_GROUP: options.oidc_required_group,
		OIDC_GROUPS_CLAIM: options.oidc_groups_claim,
		OIDC_AUTH_PARAMS: options.oidc_auth_params,
	};

	// unset or empty values are left out so the server's own configuration check names what is missing
	return Object.fromEntries(Object.entries(env).filter(([, v]) => typeof v === "string" && v !== ""));
}

/** Looks up the uid and gid of a user in /etc/passwd. */
function lookup_user(name) {
	const line = readFileSync("/etc/passwd", "utf8").split("\n").find((l) => l.startsWith(`${name}:`));

	if (!line)
		throw new Error(`user ${name} not found in /etc/passwd`);

	const [, , uid, gid] = line.split(":");

	return { uid: Number(uid), gid: Number(gid) };
}

// runs as root over a folder the node user can write, so it never follows a symlink: a link planted there
// would otherwise hand ownership of its target to node. lchown changes the link itself, and links are not entered
function chown_tree(path, uid, gid) {
	const stat = lstatSync(path);
	lchownSync(path, uid, gid);

	if (!stat.isDirectory())
		return;

	for (const name of readdirSync(path))
		chown_tree(join(path, name), uid, gid);
}

// gid first, then the supplementary groups (root's would otherwise be kept), then uid, which gives up the right to
// change the other two. Any failure stops the add-on rather than run the server as root
function drop_privileges(uid, gid) {
	try {
		process.setgid(gid);
		process.setgroups([gid]);
		process.setuid(uid);
	}
	catch (err) {
		console.error(`lubelogger-mcp add-on: could not drop privileges: ${err.message}`);
		process.exit(1);
	}

	if (process.getuid() !== uid || process.geteuid() !== uid || process.getgid() !== gid || process.getegid() !== gid) {
		console.error("lubelogger-mcp add-on: could not drop privileges");
		process.exit(1);
	}
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
	const options = JSON.parse(readFileSync("/data/options.json", "utf8"));

	const problems = check_options(options);

	if (problems.length > 0) {
		for (const problem of problems)
			console.error(`lubelogger-mcp add-on: ${problem}`);

		process.exit(1);
	}

	Object.assign(process.env, buildEnv(options));

	// the sign-in state must belong to the user the server runs as, and be unreadable by anyone else
	const node = lookup_user("node");
	mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
	chmodSync(STATE_DIR, 0o700);
	chown_tree(STATE_DIR, node.uid, node.gid);

	drop_privileges(node.uid, node.gid);
	console.error(`lubelogger-mcp add-on: options loaded, running as uid ${process.getuid()}`);

	await import("/app/dist/index.js");
}
