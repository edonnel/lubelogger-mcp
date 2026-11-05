// The sign-in screen /authorize shows: the requesting app, where it returns, and one button per sign-in method.
// Pressing a button is the approval. The page needs no JavaScript and is never framed.
import type { MethodName } from "../config.js";

/** The headers of every page the sign-in flow shows. */
export const PAGE_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "Cache-Control": "no-store",
  // never inside a frame, so a sign-in button cannot be clickjacked
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
});

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

// The look of the design's mockup: a narrow centred column on a tinted page, a wrench mark, neutral bordered
// buttons with a method icon. Fonts stay system ones, since the CSP allows no font downloads.
const STYLE =
  ":root{color-scheme:light;--bg:#f3f5f6;--ink:#16202a;--muted:#5b6873;--line:#d9dfe3;--card:#ffffff;" +
  "--btn:#f1f4f6;--btn-hover:#e6ebee;--focus:#b8650a}" +
  "@media (prefers-color-scheme: dark){:root{color-scheme:dark;--bg:#0e1419;--ink:#e4e9ed;--muted:#93a1ac;" +
  "--line:#2a3640;--card:#0d1117;--btn:#21262d;--btn-hover:#2b323b;--focus:#f0a24a}}" +
  "*{box-sizing:border-box}" +
  "body{margin:0;min-height:100vh;background:var(--bg);color:var(--ink);line-height:1.5;" +
  "font-family:system-ui,-apple-system,\"Segoe UI\",Roboto,sans-serif;font-size:15px;" +
  "padding:12vh max(16px,env(safe-area-inset-right)) 48px max(16px,env(safe-area-inset-left))}" +
  "main{max-width:360px;margin:0 auto;display:grid;gap:16px;text-align:center}" +
  ".logo{width:52px;height:52px;margin:0 auto;border-radius:14px;background:var(--ink);color:var(--bg);" +
  "display:grid;place-items:center}" +
  "h1{font-size:1.35rem;font-weight:600;margin:0;line-height:1.2;text-wrap:balance}" +
  ".box{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:10px 12px;" +
  "font-size:.86rem;color:var(--muted);text-align:left}" +
  ".box p{margin:0}.box strong{color:var(--ink)}" +
  "form{display:grid;gap:10px}" +
  "button{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;padding:9px 12px;" +
  "border:1px solid var(--line);border-radius:7px;background:var(--btn);color:var(--ink);font:inherit;" +
  "font-weight:500;cursor:pointer}" +
  "button:hover{background:var(--btn-hover)}" +
  "button:focus-visible{outline:2px solid var(--focus);outline-offset:2px}" +
  "button svg{flex:none}";

// a wrench: the server's mark at the top of every page
const LOGO =
  "<div class=\"logo\" aria-hidden=\"true\"><svg width=\"28\" height=\"28\" viewBox=\"0 0 24 24\" fill=\"none\" " +
  "stroke=\"currentColor\" stroke-width=\"1.8\" stroke-linecap=\"round\" stroke-linejoin=\"round\">" +
  "<path d=\"M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.6 2.6-2.4-.6-.6-2.4z\"/></svg></div>";

/** A small generic icon shown before a method's label, where the method has one. No third-party logos. */
const METHOD_ICON: Partial<Record<MethodName, string>> = {
  homeassistant:
    "<svg width=\"18\" height=\"18\" viewBox=\"0 0 24 24\" aria-hidden=\"true\">" +
    "<path fill=\"#41BDF5\" d=\"M12 2 2 11h3v10h14V11h3z\"/><circle cx=\"12\" cy=\"13.5\" r=\"2.4\" fill=\"#fff\"/></svg>",
};

/** A whole page in the sign-in flow's look. `body` is trusted HTML: escape anything interpolated into it. */
export function pageShell(title: string, body: string): string {
  return (
    "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">" +
    "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1,viewport-fit=cover\">" +
    `<title>${escapeHtml(title)}</title><style>${STYLE}</style></head><body><main>` +
    `${LOGO}<h1>${escapeHtml(title)}</h1>${body}</main></body></html>`
  );
}

/** The whole sign-in screen. Every interpolated value is escaped. */
export function signInPage(opts: {
  appName: string;
  returnHost: string;
  loginState: string;
  choices: MethodChoice[];
}): string {
  const buttons = opts.choices
    .map(
      (c) =>
        `<button type="submit" name="method" value="${escapeHtml(c.method)}">` +
        `${METHOD_ICON[c.method] ?? ""}${escapeHtml(c.label)}</button>`,
    )
    .join("");

  return pageShell(
    "Sign in to LubeLogger MCP",
    "<div class=\"box\"><p>" +
      `<strong>${escapeHtml(opts.appName)}</strong> wants access to your vehicle records and will return to ` +
      `<strong>${escapeHtml(opts.returnHost)}</strong>. Only continue if you started this from Claude.</p></div>` +
      "<form method=\"post\" action=\"/login\">" +
      `<input type="hidden" name="loginState" value="${escapeHtml(opts.loginState)}">` +
      `${buttons}</form>`,
  );
}
