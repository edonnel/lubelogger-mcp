// Home Assistant writes the add-on options to /data/options.json, which only root can read.
// Read them as root, prepare the state folder, then drop to the unprivileged node user before starting the server.
import { chmodSync, lchownSync, lstatSync, mkdirSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const STATE_DIR = "/data/oauth";

/** Builds the server's environment from the add-on options. A leftover mcp_path from older installs is ignored. */
export function buildEnv(options) {
	const env = {
		LUBELOGGER_URL: options.lubelogger_url,
		LUBELOGGER_API_KEY: options.lubelogger_api_key,
		AUTH_MODE: "homeassistant",
		HOME_ASSISTANT_URL: "http://homeassistant:8123",
		DATA_DIR: STATE_DIR,
		PUBLIC_URL: options.public_url,
		HOME_ASSISTANT_PUBLIC_URL: options.home_assistant_public_url,
		// optional: without it the server allows only Claude's own return addresses
		ALLOWED_REDIRECT_HOSTS: options.allowed_redirect_hosts,
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
