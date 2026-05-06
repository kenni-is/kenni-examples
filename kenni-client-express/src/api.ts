import type { Express, Request, Response } from "express";
import * as jose from "jose";

import type { Ctx } from "./index.ts";

export function mountApiRoutes(app: Express, ctx: Ctx) {
  // Lazily-built JWKS keyset, keyed off the discovered jwks_uri.
  let jwks: ReturnType<typeof jose.createRemoteJWKSet> | null = null;
  function getJwks() {
    if (!jwks) {
      jwks = jose.createRemoteJWKSet(new URL(ctx.metadata.jwks_uri!));
    }
    return jwks;
  }

  // /api/me — server-side proxy. Pulls the user's stored Kenni access token
  // and uses it to call our own /api/protected-resource. The access token
  // never leaves the server.
  app.get("/api/me", async (req, res) => {
    if (!ctx.apiEnabled) {
      res.status(503).json({
        error: "KENNI_API_SCOPE is not configured on this app.",
      });
      return;
    }
    const accessToken = req.session.tokens?.access_token;
    if (!accessToken) {
      res.status(401).json({ error: "Not signed in." });
      return;
    }

    const upstream = await fetch(`${ctx.baseUrl}/api/protected-resource`, {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    res
      .status(upstream.status)
      .type("application/json")
      .send(await upstream.text());
  });

  // /api/client-credentials — POST grant_type=client_credentials with HTTP
  // Basic auth (RFC 6749 §2.3.1) and decode the access token's claims for
  // display.
  app.post("/api/client-credentials", async (_req, res) => {
    if (!ctx.m2mEnabled) {
      res.status(503).json({
        error:
          "Set KENNI_M2M_CLIENT_ID, KENNI_M2M_CLIENT_SECRET, and KENNI_M2M_SCOPE.",
      });
      return;
    }

    // RFC 6749 §2.3.1: form-urlencode each credential before joining and
    // base64-encoding for HTTP Basic. Matters when the secret has `:` or `%`.
    const basic = Buffer.from(
      `${encodeURIComponent(ctx.m2mClientId!)}:${encodeURIComponent(ctx.m2mClientSecret!)}`,
    ).toString("base64");

    const body = new URLSearchParams({
      grant_type: "client_credentials",
      scope: ctx.m2mScope!,
    });

    const upstream = await fetch(ctx.metadata.token_endpoint!, {
      method: "POST",
      headers: {
        authorization: `Basic ${basic}`,
        "content-type": "application/x-www-form-urlencoded",
        accept: "application/json",
      },
      body,
    });

    const tokenSet = await upstream.json();
    if (!upstream.ok) {
      res.status(upstream.status).json({
        error: "Token endpoint rejected the request.",
        detail: tokenSet,
      });
      return;
    }

    let claims: jose.JWTPayload | null = null;
    try {
      claims = jose.decodeJwt(tokenSet.access_token);
    } catch {
      /* opaque token — leave claims null */
    }

    res.json({
      token_type: tokenSet.token_type,
      expires_in: tokenSet.expires_in,
      scope: tokenSet.scope,
      claims,
    });
  });

  // /api/protected-resource — bearer-protected endpoint demonstrating local
  // access-token verification via JOSE: signature (against Kenni's JWKS),
  // issuer, audience, expiry. Then asserts KENNI_API_SCOPE is on the token.
  app.get("/api/protected-resource", async (req: Request, res: Response) => {
    if (!ctx.apiEnabled) {
      res.status(503).json({
        error: "KENNI_API_SCOPE is not configured on this app.",
      });
      return;
    }

    const authz = req.header("authorization") ?? "";
    if (!authz.toLowerCase().startsWith("bearer ")) {
      res
        .status(401)
        .json({ error: "Missing Authorization: Bearer header." });
      return;
    }
    const raw = authz.slice("Bearer ".length).trim();

    let payload: jose.JWTPayload;
    try {
      const result = await jose.jwtVerify(raw, getJwks(), {
        issuer: ctx.issuer,
        audience: ctx.apiAudience,
      });
      payload = result.payload;
    } catch (err) {
      res.status(401).json({
        error: "Token verification failed.",
        detail: String(err),
      });
      return;
    }

    const scopes = String(payload.scope ?? "").split(" ").filter(Boolean);
    if (!scopes.includes(ctx.apiScope!)) {
      res.status(403).json({
        error: `Token is missing required scope '${ctx.apiScope}'.`,
        scopes,
      });
      return;
    }

    res.json({
      message: "Halló!",
      served_by: "Node.js / Express (openid-client) example",
      sub: payload.sub,
      national_id: payload.national_id,
      scopes,
      expires_at: payload.exp
        ? new Date(payload.exp * 1000).toISOString()
        : null,
    });
  });
}
