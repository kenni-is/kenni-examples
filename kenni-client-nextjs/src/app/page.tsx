import { headers } from "next/headers";

import { PageContainer } from "@kenni-example/components/ui";
import { auth } from "@kenni-example/lib/auth";
import { features } from "@kenni-example/lib/env";

import styles from "./page.module.css";

const Home = async () => {
  const session = await auth.api.getSession({ headers: await headers() });

  return (
    <main className={styles.main}>
      <h1>
        {session?.user
          ? `Welcome ${session.user.name ?? session.user.email ?? ""}`
          : "Kenni — Next.js (better-auth) example"}
      </h1>
      <PageContainer signedIn={Boolean(session?.user)} features={features} />
    </main>
  );
};

export default Home;
