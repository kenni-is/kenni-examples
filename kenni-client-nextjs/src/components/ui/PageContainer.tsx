"use client";

import { useState } from "react";

import {
  FetchButton,
  SignInButton,
  SignOutButton,
} from "@kenni-example/components";

import styles from "./PageContainer.module.css";

type PageContainerProps = {
  signedIn: boolean;
};

export const PageContainer = ({ signedIn }: PageContainerProps) => {
  const [data, setData] = useState<Record<string, unknown> | null>(null);

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
            <SignOutButton />
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
