// Mounts the OAuth endpoints and returns the bearer check for /mcp.
import express from "express";
import { requireBearerAuth } from "@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js";
import { getOAuthProtectedResourceMetadataUrl, mcpAuthRouter } from "@modelcontextprotocol/sdk/server/auth/router.js";
import type { LoginProvider } from "./provider.js";

/** Seconds Claude is told to wait before retrying a refresh while the login method is unreachable. */
const RETRY_AFTER_SECONDS = 30;

// The SDK's token handler answers every OAuth error with 400. A refresh that failed only because the
// login method was unreachable must be 503 temporarily_unavailable, so Claude retries instead of giving up.
const temporarilyUnavailableAs503: express.RequestHandler = (_req, res, next) => {
  const json = res.json.bind(res);
  res.json = (body?: unknown) => {
    if (
      res.statusCode === 400 &&
      typeof body === "object" &&
      body !== null &&
      (body as { error?: unknown }).error === "temporarily_unavailable"
    )
      res.status(503).set("Retry-After", String(RETRY_AFTER_SECONDS));
    return json(body);
  };
  next();
};

export function mountOAuth(
  app: express.Express,
  opts: { publicUrl: string; provider: LoginProvider },
): express.RequestHandler {
  const { publicUrl, provider } = opts;
  const resource = new URL(`${publicUrl}/mcp`);

  // one proxy (the tunnel) in front: lets the SDK's rate limiter key on the client's X-Forwarded-For address
  app.set("trust proxy", 1);

  app.use("/token", temporarilyUnavailableAs503);
  app.use(
    mcpAuthRouter({
      provider,
      issuerUrl: new URL(publicUrl),
      resourceServerUrl: resource,
      // the SDK's default expires client secrets after 30 days, which would end a 90-day connection early
      clientRegistrationOptions: { clientSecretExpirySeconds: 0 },
    }),
  );
  app.post("/login", express.urlencoded({ extended: false, limit: "4kb" }), (req, res) => provider.handleApprove(req, res));
  app.get("/login/callback", (req, res) => provider.handleCallback(req, res));

  return requireBearerAuth({
    verifier: provider,
    resourceMetadataUrl: getOAuthProtectedResourceMetadataUrl(resource),
  });
}
