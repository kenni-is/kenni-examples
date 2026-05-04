"use client";

import { useRouter } from "next/navigation";

import { authClient } from "@kenni-example/lib/auth-client";

// Local sign-out only — clears the better-auth session cookie. The user
// stays signed in to Kenni, so the next "Continue with Kenni" click will
// re-authenticate them silently. For a full sign-out, use the
// "RP-initiated logout" button instead.
export const SignOutButton = () => {
  const router = useRouter();
  return (
    <button
      onClick={async () => {
        await authClient.signOut();
        router.refresh();
      }}
    >
      Sign out (local)
    </button>
  );
};
