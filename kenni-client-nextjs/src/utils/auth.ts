import NextAuth, { NextAuthConfig, Session, User } from "next-auth";
import { JWT } from "@auth/core/jwt";

import { cookies } from "./cookies";
import Kenni from "./provider";

export const { auth, handlers, signIn, signOut } = NextAuth({
  providers: [Kenni],
  cookies,
  callbacks: {
    session: ({ session, token }: { session: Session; token?: JWT }) => {
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
    jwt: ({ user, token }: { user?: User; token: JWT }) => {
      if (user) {
        token.id = user.id;
        token.sub = user.sub;
        token.name = user.name as string;
        token.idToken = user.idToken;
        token.accessToken = user.accessToken;
        token.refreshToken = user.refreshToken;
      }

      return token;
    },
  },
  session: { strategy: "jwt" },
} satisfies NextAuthConfig);
