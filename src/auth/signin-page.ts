// The sign-in screen /authorize shows: the requesting app, where it returns, and one button per sign-in method.
// Pressing a button is the approval. The page needs no JavaScript and is never framed.
import type { MethodName } from "../config.js";

/** The headers of every page the sign-in flow shows. */
export const PAGE_HEADERS: Record<string, string> = {
  "Cache-Control": "no-store",
  // never inside a frame, so a sign-in button cannot be clickjacked
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
};

export type MethodChoice = { method: MethodName; label: string };

/** Each method's button text. Step 2 replaces the `oidc` label with the provider's display name. */
export const BUTTON_LABEL: Record<MethodName, string> = {
  homeassistant: "Continue with Home Assistant",
  oidc: "Continue with single sign-on",
  "lubelogger-password": "Sign in with LubeLogger",
  "lubelogger-key": "Sign in with an API key",
};

const HTML_ESCAPES: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" };

export function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (ch) => HTML_ESCAPES[ch] ?? ch);
}

const STYLE =
  ":root{color-scheme:light dark;--fg:#1f2328;--bg:#ffffff;--muted:#59636e;--box:#f6f8fa;--line:#d1d9e0;" +
  "--button:#1f6feb;--button-fg:#ffffff}" +
  "@media (prefers-color-scheme: dark){:root{--fg:#e6edf3;--bg:#0d1117;--muted:#9198a1;--box:#151b23;" +
  "--line:#3d444d;--button:#388bfd;--button-fg:#ffffff}}" +
  "body{font-family:system-ui,sans-serif;color:var(--fg);background:var(--bg);max-width:26rem;" +
  "margin:3rem auto;padding:0 1rem;line-height:1.5}" +
  "h1{font-size:1.5rem;margin:0 0 1.25rem}" +
  ".request{background:var(--box);border:1px solid var(--line);border-radius:.5rem;padding:.75rem 1rem;margin:0 0 1.5rem}" +
  ".request p{margin:0}.request p+p{margin-top:.5rem;color:var(--muted)}" +
  "form{display:flex;flex-direction:column;gap:.75rem}" +
  "button{font:inherit;font-weight:600;padding:.7rem 1rem;border:0;border-radius:.5rem;cursor:pointer;" +
  "background:var(--button);color:var(--button-fg)}" +
  "button:focus-visible{outline:2px solid var(--fg);outline-offset:2px}";

/** The whole sign-in screen. Every interpolated value is escaped. */
export function signInPage(opts: {
  appName: string;
  returnHost: string;
  loginState: string;
  choices: MethodChoice[];
}): string {
  const title = "Sign in to LubeLogger MCP";
  const buttons = opts.choices
    .map((c) => `<button type="submit" name="method" value="${escapeHtml(c.method)}">${escapeHtml(c.label)}</button>`)
    .join("");

  return (
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
    `<title>${escapeHtml(title)}</title><style>${STYLE}</style></head><body>` +
    `<h1>${escapeHtml(title)}</h1>` +
    "<div class=\"request\">" +
    `<p><strong>${escapeHtml(opts.appName)}</strong> wants to connect to LubeLogger MCP and will return to ` +
    `<strong>${escapeHtml(opts.returnHost)}</strong>.</p>` +
    "<p>Only continue if you started this from Claude.</p></div>" +
    "<form method=\"post\" action=\"/login\">" +
    `<input type="hidden" name="loginState" value="${escapeHtml(opts.loginState)}">` +
    `${buttons}</form></body></html>`
  );
}
