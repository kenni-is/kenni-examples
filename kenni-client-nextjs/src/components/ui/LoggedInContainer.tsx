"use client";

import { useState } from "react";

import { FetchButton, SignOutButton } from "@kenni-example/components";

import styles from "./LoggedInContainer.module.css";

export const LoggedInContainer = () => {
  const [data, setData] = useState<Record<string, unknown> | null>(null);

  return (
    <>
      <div className={styles.loggedInContainer}>
        <FetchButton onFetched={(data) => setData(data)} />
        <SignOutButton />
      </div>
      <div className={styles.response}>
        {data && <pre>{JSON.stringify(data, null, 2)}</pre>}
      </div>
    </>
  );
};
