// Kenni — Node.js / Express example.
//
// Sign in with Kenni (OIDC: Authorization Code + PKCE), call a protected
// API endpoint with the user's access token, and run a client-credentials
// grant. Uses openid-client v6 — the reference OIDC library for Node and
// the same one Auth.js / NextAuth / better-auth wrap internally.

import "dotenv/config";

import express from "express";
import session from "express-session";
import * as openid from "openid-client";

import { mountAuthRoutes } from "./auth.ts";
import { mountApiRoutes } from "./api.ts";
import { renderIndex } from "./views.ts";

declare module "express-session" {
  interface SessionData {
    state?: string;
    codeVerifier?: string;
    tokens?: {
      access_token: string;
      id_token?: string;
      refresh_token?: string;
    };
    user?: { sub: string; name?: string; national_id?: string };
  }
}

function required(key: string): string {
  const value = process.env[key];
  if (!value) {
    console.error(`missing required env var: ${key}`);
    process.exit(1);
  }
  return value;
}

const PORT = Number(process.env.PORT ?? 3002);
const ISSUER = required("KENNI_ISSUER");
const CLIENT_ID = required("KENNI_CLIENT_ID");
const CLIENT_SECRET = required("KENNI_CLIENT_SECRET");
const API_SCOPE = process.env.KENNI_API_SCOPE || undefined;
const API_AUDIENCE =
  process.env.KENNI_API_AUDIENCE || `${CLIENT_ID}-api`;
const M2M_CLIENT_ID = process.env.KENNI_M2M_CLIENT_ID || undefined;
const M2M_CLIENT_SECRET = process.env.KENNI_M2M_CLIENT_SECRET || undefined;
const M2M_SCOPE = process.env.KENNI_M2M_SCOPE || undefined;

const apiEnabled = Boolean(API_SCOPE);
const m2mEnabled = Boolean(M2M_CLIENT_ID && M2M_CLIENT_SECRET && M2M_SCOPE);

// Discovery once at startup. The Configuration object holds the parsed
// metadata and client credentials for every subsequent openid-client call.
//
// openid-client v6 refuses non-HTTPS issuers by default — even for the
// initial discovery fetch. For a local Kenni instance on http://localhost:...,
// opt in via the `execute: [allowInsecureRequests]` option. Production
// issuers are always HTTPS, so this branch is a no-op there.
const issuerUrl = new URL(ISSUER);
const config = await openid.discovery(
  issuerUrl,
  CLIENT_ID,
  CLIENT_SECRET,
  undefined,
  issuerUrl.protocol === "http:"
    ? { execute: [openid.allowInsecureRequests] }
    : undefined,
);

// Cache the discovery doc — we read end_session_endpoint, token_endpoint,
// and jwks_uri from it.
const metadata = config.serverMetadata();

const baseUrl = `http://localhost:${PORT}`;

export type Ctx = {
  config: openid.Configuration;
  metadata: openid.ServerMetadata;
  issuer: string;
  clientId: string;
  apiScope?: string;
  apiAudience: string;
  apiEnabled: boolean;
  m2mEnabled: boolean;
  m2mClientId?: string;
  m2mClientSecret?: string;
  m2mScope?: string;
  redirectUri: string;
  postLogoutRedirectUri: string;
  baseUrl: string;
};

const ctx: Ctx = {
  config,
  metadata,
  issuer: ISSUER,
  clientId: CLIENT_ID,
  apiScope: API_SCOPE,
  apiAudience: API_AUDIENCE,
  apiEnabled,
  m2mEnabled,
  m2mClientId: M2M_CLIENT_ID,
  m2mClientSecret: M2M_CLIENT_SECRET,
  m2mScope: M2M_SCOPE,
  redirectUri: `${baseUrl}/auth/callback`,
  postLogoutRedirectUri: `${baseUrl}/`,
  baseUrl,
};

const app = express();

app.use(
  session({
    secret:
      process.env.SESSION_SECRET ??
      "dev-only-please-replace-me-with-a-random-32-char-string",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      maxAge: 8 * 60 * 60 * 1000,
    },
  }),
);

app.get("/", (req, res) => {
  res.type("html").send(
    renderIndex({
      signedIn: Boolean(req.session.tokens?.id_token),
      name:
        req.session.user?.name ??
        req.session.user?.sub ??
        "",
      apiEnabled,
      m2mEnabled,
    }),
  );
});

mountAuthRoutes(app, ctx);
mountApiRoutes(app, ctx);

app.listen(PORT, "localhost", () => {
  console.log(`listening on ${baseUrl}`);
});
