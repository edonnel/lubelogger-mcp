// The sign-in screen /authorize shows: the requesting app, where it returns, a button per redirect method and a form
// per LubeLogger method. Pressing a button, or a form check that succeeds, is the approval.
// The page needs no JavaScript and is never framed.
import type { MethodName } from "../config.js";

/** The headers of every page the sign-in flow shows. */
export const PAGE_HEADERS: Readonly<Record<string, string>> = Object.freeze({
  "Cache-Control": "no-store",
  // never inside a frame, so a sign-in button cannot be clickjacked
  "X-Frame-Options": "DENY",
  "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
});

export type MethodChoice = { method: MethodName; label: string };

/** Each method's fallback button text. app.ts gives the provider an `oidc` label naming the OIDC provider. */
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
  "button svg{flex:none}" +
  ".or{display:flex;align-items:center;gap:10px;color:var(--muted);font-size:.86rem}" +
  ".or::before,.or::after{content:\"\";flex:1;border-top:1px solid var(--line)}" +
  "label{display:grid;gap:4px;text-align:left;font-size:.86rem;color:var(--muted)}" +
  "input{width:100%;padding:8px 10px;border:1px solid var(--line);border-radius:7px;background:var(--card);" +
  "color:var(--ink);font:inherit}" +
  "input:focus-visible{outline:2px solid var(--focus);outline-offset:1px}" +
  "details{display:grid;gap:10px;text-align:left}" +
  "details[open]>summary{margin-bottom:10px}" +
  "summary{cursor:pointer;color:var(--muted);font-size:.86rem;text-align:center}" +
  ".error{border-color:#c0392b;color:var(--ink)}";

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
  // a generic key, in the text colour: any OpenID Connect provider
  oidc:
    "<svg width=\"18\" height=\"18\" viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" " +
    "stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\">" +
    "<circle cx=\"7.5\" cy=\"15.5\" r=\"4.5\"/><path d=\"m10.7 12.3 9.8-9.8M17 6l3 3M14.5 8.5l2 2\"/></svg>",
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

/** The sign-in forms, by the kind of credentials they take. */
export type FormKind = "password" | "key";

/** The method each form posts. */
const FORM_METHOD: Record<FormKind, MethodName> = { password: "lubelogger-password", key: "lubelogger-key" };

/** An error box, shown above the form it belongs to. */
function errorBox(message: string): string {
  return `<div class="box error" role="alert"><p>${escapeHtml(message)}</p></div>`;
}

/** A form's opening tag and the hidden fields every form posts: the one-time state and the method. */
function formStart(loginState: string, kind: FormKind): string {
  return (
    "<form method=\"post\" action=\"/login\">" +
    `<input type="hidden" name="loginState" value="${escapeHtml(loginState)}">` +
    `<input type="hidden" name="method" value="${escapeHtml(FORM_METHOD[kind])}">`
  );
}

/**
 * The whole sign-in screen: the redirect methods' buttons, then the LubeLogger forms. After a failed attempt it is
 * shown again with `error` above the form that failed and `username` kept. A typed password or key is never put
 * back on the page. Every interpolated value is escaped.
 */
export function signInPage(opts: {
  appName: string;
  returnHost: string;
  loginState: string;
  choices: MethodChoice[];
  forms?: { password?: boolean; key?: boolean };
  error?: { form: FormKind; message: string };
  username?: string;
}): string {
  const errorFor = (kind: FormKind) => (opts.error?.form === kind ? errorBox(opts.error.message) : "");
  const state = `<input type="hidden" name="loginState" value="${escapeHtml(opts.loginState)}">`;

  const buttons = opts.choices.length
    ? "<form method=\"post\" action=\"/login\">" +
      state +
      opts.choices
        .map(
          (c) =>
            `<button type="submit" name="method" value="${escapeHtml(c.method)}">` +
            `${METHOD_ICON[c.method] ?? ""}${escapeHtml(c.label)}</button>`,
        )
        .join("") +
      "</form>"
    : "";

  const password = opts.forms?.password
    ? errorFor("password") +
      formStart(opts.loginState, "password") +
      "<label>Username<input type=\"text\" name=\"username\" autocomplete=\"username\" " +
      `autocapitalize="none" spellcheck="false" required${opts.username ? ` value="${escapeHtml(opts.username)}"` : ""}></label>` +
      "<label>Password<input type=\"password\" name=\"password\" autocomplete=\"current-password\" required></label>" +
      `<button type="submit">${escapeHtml(BUTTON_LABEL["lubelogger-password"])}</button></form>`
    : "";

  const keyForm =
    errorFor("key") +
    formStart(opts.loginState, "key") +
    "<label>LubeLogger API key<input type=\"password\" name=\"apiKey\" autocomplete=\"off\" required></label>" +
    `<button type="submit">${escapeHtml(BUTTON_LABEL["lubelogger-key"])}</button></form>`;
  // behind a closed "instead" toggle next to the password form, opened by its own error; on its own otherwise
  const key = !opts.forms?.key
    ? ""
    : password
      ? `<details${opts.error?.form === "key" ? " open" : ""}><summary>Use a LubeLogger API key instead</summary>${keyForm}</details>`
      : keyForm;

  const divider = buttons && (password || key) ? "<div class=\"or\">or</div>" : "";

  return pageShell(
    "Sign in to LubeLogger MCP",
    "<div class=\"box\"><p>" +
      `<strong>${escapeHtml(opts.appName)}</strong> wants access to your vehicle records and will return to ` +
      `<strong>${escapeHtml(opts.returnHost)}</strong>. Only continue if you started this from Claude.</p></div>` +
      buttons +
      divider +
      password +
      key,
  );
}
