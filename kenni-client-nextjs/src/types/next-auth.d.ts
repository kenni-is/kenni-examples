import { DefaultSession } from "next-auth/next";

declare module "next-auth" {
  /**
   * Returned by `useSession`, `getSession` and received as a prop on the `SessionProvider` React Context
   */
  interface Session extends DefaultSession {
    user: {
      sub: string;
      name: string;
      idToken: string;
    };
  }

  interface User {
    sub: string;
    name: string;
    idToken: string;
    accessToken: string;
    refreshToken: string;
  }
}

declare module "next-auth/jwt" {
  /** Returned by the `jwt` callback and `getToken`, when using JWT sessions */
  interface JWT {
    sub: string;
    name: string;
    idToken: string;
    accessToken: string;
    refreshToken: string;
  }
}
