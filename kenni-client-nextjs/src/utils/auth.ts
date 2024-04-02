import { NextAuthOptions } from "next-auth";
import { TokenSetParameters } from "openid-client";

import { cookies } from "./cookies";

const issuer = process.env.KENNI_ISSUER;
const scope = process.env.KENNI_SCOPE;
const redirectUri = process.env.KENNI_REDIRECT_URI;
const clientId = process.env.KENNI_CLIENT_ID;
const clientSecret = process.env.KENNI_CLIENT_SECRET;
const apiScope = process.env.KENNI_API_SCOPE;

export const authOptions: NextAuthOptions = {
  providers: [
    {
      id: "kenni",
      name: "Kenni NextJs Example",
      type: "oauth",
      wellKnown: `${issuer}/.well-known/openid-configuration`,
      authorization: {
        params: {
          scope: `${scope} ${apiScope}`,
          redirect_uri: redirectUri,
          ui_locale: "is", // Optional. Valid options, "is" or "en"
        },
      },
      clientId,
      clientSecret,
      idToken: true,
      checks: ["pkce", "state", "nonce"],
      profile: (
        profile: Record<string, string>,
        tokens: TokenSetParameters
      ) => {
        return {
          id: profile.sub,
          sub: profile.sub,
          name: profile.name,
          accessToken: tokens.access_token ?? "",
          idToken: tokens.id_token ?? "",
          refreshToken: tokens.refresh_token ?? "",
        };
      },
    },
  ],
  cookies,
  callbacks: {
    session: ({ session, token }) => {
      if (token) {
        const { sub, name, idToken } = token;

        // Add claims that are safe for the client side
        session.user = {
          sub,
          name,
          idToken,
        };
      }

      return session;
    },
    jwt: ({ user, token }) => {
      if (user) {
        token.id = user.id;
        token.sub = user.sub;
        token.name = user.name;
        token.idToken = user.idToken;
        token.accessToken = user.accessToken;
        token.refreshToken = user.refreshToken;
      }

      return token;
    },
  },
};
