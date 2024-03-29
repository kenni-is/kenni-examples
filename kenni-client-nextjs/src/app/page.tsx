import styles from "./page.module.css";
import { SignInButton } from "@kenni-example/components";
import { LoggedInContainer } from "@kenni-example/components/ui";

import { getSession } from "./session";

const Home = async () => {
  const session = await getSession();

  return (
    <main className={styles.main}>
      {session?.user ? (
        <>
          <h1>Welcome {session.user.name}</h1>
          <LoggedInContainer />
        </>
      ) : (
        <SignInButton />
      )}
    </main>
  );
};

export default Home;
