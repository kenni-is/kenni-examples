"use client";

import { authClient } from "@kenni-example/lib/auth-client";

export const SwitchDelegationButton = () => {
  return (
    <button
      onClick={() =>
        authClient.signIn.oauth2({
          providerId: "kenni",
          callbackURL: "/",
          additionalData: { prompt: "delegation" },
        })
      }
    >
      Switch delegation
    </button>
  );
};
