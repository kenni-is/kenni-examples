import styles from "./page.module.css";
import { PageContainer } from "@kenni-example/components/ui";

import { auth } from "@kenni-example/utils/auth";

const Home = async () => {
  const session = await auth();

  return (
    <main className={styles.main}>
      {session?.user && (
        <>
          <h1>Welcome {session.user.name}</h1>
        </>
      )}
      <PageContainer signedIn={Boolean(session?.user)} />
    </main>
  );
};

export default Home;
