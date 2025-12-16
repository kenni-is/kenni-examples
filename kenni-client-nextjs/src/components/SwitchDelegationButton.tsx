"use client";

import { signIn } from "next-auth/react";

export const SwitchDelegationButton = () => {
  return <button onClick={() => signIn("kenni", undefined, {prompt: 'delegation'})}>Switch delegation</button>;
};
