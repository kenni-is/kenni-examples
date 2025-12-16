"use client";

import { signIn } from "next-auth/react";

export const SignInButton = () => {
  return <>
    <button onClick={() => signIn("kenni")}>Sign in</button>
    <button onClick={() => signIn("kenni", undefined, {prompt: 'delegation'})}>Sign in with delegation</button>
  </>;
};
