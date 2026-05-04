"use client";

import { useState } from "react";

import {
  FetchButton,
  SignInButton,
  SignOutButton,
  SwitchDelegationButton,
} from "@kenni-example/components";

import styles from "./PageContainer.module.css";

type PageContainerProps = {
  signedIn: boolean;
  features: { apiCall: boolean; clientCredentials: boolean };
};

export const PageContainer = ({ signedIn, features }: PageContainerProps) => {
  const [data, setData] = useState<Record<string, unknown> | null>(null);

  return (
    <>
      <div className={styles.buttonStack}>
        {!signedIn && <SignInButton />}

        {signedIn && features.apiCall && (
          <FetchButton
            title="Call protected resource"
            url="/api/me"
            onFetched={setData}
          />
        )}

        {features.clientCredentials && (
          <FetchButton
            title="Client credentials grant"
            url="/api/client-credentials"
            method="POST"
            onFetched={setData}
          />
        )}

        {signedIn && (
          <>
            <SwitchDelegationButton />
            <SignOutButton />
            <a href="/api/sign-out" className={styles.linkButton}>
              <button>RP-initiated logout</button>
            </a>
          </>
        )}
      </div>

      {data && (
        <pre className={styles.details}>{JSON.stringify(data, null, 2)}</pre>
      )}
    </>
  );
};
