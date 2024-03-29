"use client";

import { type PropsWithChildren } from "react";
import { SessionProvider } from "next-auth/react";
import { Session } from "next-auth";

type RootProviderProps = PropsWithChildren<{
  session: Session | null;
}>;

export const RootProvider = ({ children, session }: RootProviderProps) => {
  return <SessionProvider session={session}>{children}</SessionProvider>;
};
