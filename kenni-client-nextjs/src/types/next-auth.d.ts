import { type DefaultSession } from "next-auth";

declare module "next-auth" {
  interface Session {
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
