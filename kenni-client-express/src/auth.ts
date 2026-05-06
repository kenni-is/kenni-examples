import type { Express } from "express";
import * as openid from "openid-client";

import type { Ctx } from "./index.ts";

export function mountAuthRoutes(app: Express, ctx: Ctx) {
  const scopes = [
    "openid",
    "profile",
    "national_id",
    "offline_access",
    ...(ctx.apiScope ? [ctx.apiScope] : []),
  ].join(" ");

  app.get("/auth/login", async (req, res) => {
    const codeVerifier = openid.randomPKCECodeVerifier();
    const codeChallenge = await openid.calculatePKCECodeChallenge(codeVerifier);
    const state = openid.randomState();

    req.session.codeVerifier = codeVerifier;
    req.session.state = state;

    const url = openid.buildAuthorizationUrl(ctx.config, {
      redirect_uri: ctx.redirectUri,
      scope: scopes,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
      state,
    });

    res.redirect(url.href);
  });

  app.get("/auth/callback", async (req, res) => {
    if (!req.session.codeVerifier || !req.session.state) {
      res.status(400).send("session expired — please retry sign-in");
      return;
    }

    try {
      const callbackUrl = new URL(req.originalUrl, ctx.baseUrl);
      const tokens = await openid.authorizationCodeGrant(
        ctx.config,
        callbackUrl,
        {
          pkceCodeVerifier: req.session.codeVerifier,
          expectedState: req.session.state,
        },
      );

      const claims = (tokens.claims() ?? {}) as Record<string, unknown>;
      const fullName = (claims.name as string | undefined) ?? "";
      const composed = [claims.given_name, claims.family_name]
        .filter((s): s is string => typeof s === "string" && s.length > 0)
        .join(" ")
        .trim();
      const name = fullName || composed || undefined;

      req.session.tokens = {
        access_token: tokens.access_token,
        id_token: tokens.id_token,
        refresh_token: tokens.refresh_token,
      };
      req.session.user = {
        sub: String(claims.sub ?? ""),
        name,
        national_id: claims.national_id as string | undefined,
      };
      req.session.codeVerifier = undefined;
      req.session.state = undefined;

      res.redirect("/");
    } catch (err) {
      res
        .status(500)
        .send(`code exchange failed: ${(err as Error).message}`);
    }
  });

  // Local sign-out only — Kenni's session cookie is untouched, so the next
  // sign-in is silent. Use /auth/rp-logout to also end Kenni's session.
  app.post("/auth/logout", (req, res) => {
    req.session.destroy(() => {
      res.redirect("/");
    });
  });

  // RP-initiated logout: clear the local session, then redirect the browser
  // to Kenni's end_session_endpoint with id_token_hint +
  // post_logout_redirect_uri. Order matters — if the Kenni redirect fails,
  // the local session is still cleared.
  app.post("/auth/rp-logout", (req, res) => {
    if (!ctx.metadata.end_session_endpoint) {
      res
        .status(500)
        .send("issuer does not advertise end_session_endpoint");
      return;
    }

    const idToken = req.session.tokens?.id_token;
    const url = openid.buildEndSessionUrl(ctx.config, {
      ...(idToken ? { id_token_hint: idToken } : {}),
      post_logout_redirect_uri: ctx.postLogoutRedirectUri,
    });

    req.session.destroy(() => {
      res.redirect(url.href);
    });
  });
}
