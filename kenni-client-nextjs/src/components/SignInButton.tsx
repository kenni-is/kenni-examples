"use client";

import { authClient } from "@kenni-example/lib/auth-client";

export const SignInButton = () => {
  return (
    <>
      <button
        onClick={() =>
          authClient.signIn.oauth2({
            providerId: "kenni",
            callbackURL: "/",
          })
        }
      >
        Continue with Kenni
      </button>
      <button
        onClick={() =>
          authClient.signIn.oauth2({
            providerId: "kenni",
            callbackURL: "/",
            additionalData: { prompt: "delegation" },
          })
        }
      >
        Continue with Delegation
      </button>
    </>
  );
};
