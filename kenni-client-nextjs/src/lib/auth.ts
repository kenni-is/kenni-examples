import { betterAuth } from "better-auth";
import { genericOAuth } from "better-auth/plugins";
import { nextCookies } from "better-auth/next-js";
import { decodeJwt } from "jose";

import { env } from "./env";

const scopes = ["openid", "profile", "national_id", "offline_access"];
if (env.KENNI_API_SCOPE) scopes.push(env.KENNI_API_SCOPE);

// WORKAROUND: better-auth requires every user to have BOTH `email` and
// `name`, and rejects the sign-in callback with `email_is_missing` /
// `name_is_missing` if the IdP doesn't return one
// (see better-auth/plugins/generic-oauth/routes.mjs).
// Kenni does not guarantee either:
//   - `email` is consent-gated and most apps don't request it.
//   - `name` is released via the `profile` scope but may be empty for some
//     users (e.g. delegations, test accounts).
// We synthesize deterministic placeholders so better-auth is happy. Real
// values (when released by Kenni) still win.
const kenniMapProfileToUser = (profile: Record<string, unknown>) => ({
  email:
    (profile.email as string | undefined) ??
    `${profile.sub}@no-reply.users.kenni.is`,
  emailVerified: Boolean(profile.email_verified),
  name:
    (profile.name as string | undefined) ||
    [profile.given_name, profile.family_name].filter(Boolean).join(" ") ||
    "Kenni user",
});

// Stateless mode: no `database:` is configured, so better-auth stores the
// session and account state in signed cookies. No persistence layer needed.
// See https://better-auth.com/docs/concepts/session-management#stateless-session-management
export const auth = betterAuth({
  plugins: [
    genericOAuth({
      config: [
        {
          providerId: "kenni",
          discoveryUrl: `${env.KENNI_ISSUER}/.well-known/openid-configuration`,
          clientId: env.KENNI_CLIENT_ID,
          clientSecret: env.KENNI_CLIENT_SECRET,
          scopes,
          pkce: true,
          accessType: "offline",
          mapProfileToUser: kenniMapProfileToUser,
          // Kenni returns `name`/`given_name`/`family_name` in the id_token
          // (with the `profile` scope), not in the userinfo response.
          // better-auth's default `getUserInfo` only uses id_token claims
          // when BOTH `sub` and `email` are present — and Kenni doesn't put
          // email in the id_token — so it falls through to userinfo and we
          // lose the name. Use the id_token claims directly instead.
          getUserInfo: async (tokens) => {
            if (!tokens.idToken) return null;
            const claims = decodeJwt(tokens.idToken) as Record<string, unknown>;
            return {
              ...claims,
              id: String(claims.sub ?? ""),
              email: claims.email as string | undefined,
              emailVerified: Boolean(claims.email_verified),
              name: claims.name as string | undefined,
              image: claims.picture as string | undefined,
            };
          },
          // better-auth doesn't accept `prompt` on `signIn.oauth2`, but
          // `authorizationUrlParams` as a function receives the request ctx,
          // so we forward `additionalData.prompt` from the client into the
          // authorization URL. This lets the same provider serve plain
          // sign-in and `prompt=delegation` re-auth without needing a second
          // provider + redirect URI.
          authorizationUrlParams: (ctx) => {
            const prompt = (
              ctx.body as { additionalData?: { prompt?: string } } | undefined
            )?.additionalData?.prompt;
            return prompt ? { prompt } : ({} as Record<string, string>);
          },
        },
      ],
    }),
    // Must be the LAST plugin per better-auth docs — sets cookies returned
    // by server actions / route handlers.
    nextCookies(),
  ],
});
