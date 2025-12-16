"use client";

import { useState } from "react";
import { signOut, useSession } from "next-auth/react";

import {
  FetchButton,
  SignInButton,
  SignOutButton,
  SwitchDelegationButton,
} from "@kenni-example/components";

import styles from "./PageContainer.module.css";

type PageContainerProps = {
  signedIn: boolean;
};

const postLogoutUrl = process.env.NEXT_PUBLIC_POST_LOGOUT_URL as string;

export const PageContainer = ({ signedIn }: PageContainerProps) => {
  const [data, setData] = useState<Record<string, unknown> | null>(null);

  const { data: session } = useSession();

  return (
    <>
      <div className={styles.loggedInContainer}>
        {!signedIn && <SignInButton />}
        <FetchButton
          title="Client credentials"
          url="/api/client-credentials"
          onFetched={(data) => setData(data)}
        />
        {signedIn && (
          <>
            <FetchButton onFetched={(data) => setData(data)} />
            <SwitchDelegationButton />
            <SignOutButton />
            <button
              onClick={async () => {
                // It would be better to rather have the post_logout_redirect_uri call signOut(), since if RP-initiated logout fails,
                // the user's local session will still be cleared
                await signOut();

                // Navigate to the RP-initiated logout endpoint
                location.href = `/api/sign-out?post_logout_redirect_uri=${encodeURIComponent(
                  postLogoutUrl
                )}&hint=${session?.user?.idToken}`;
              }}
            >
              RP-initiated Logout
            </button>
          </>
        )}
      </div>
      <div className={styles.response}>
        {data && (
          <pre className={styles.details}>{JSON.stringify(data, null, 2)}</pre>
        )}
      </div>
    </>
  );
};
