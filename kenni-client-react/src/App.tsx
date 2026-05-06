import { useAuth } from "react-oidc-context";

import { PageContainer } from "./PageContainer";
import styles from "./App.module.css";

const headingFor = (
  isAuthenticated: boolean,
  name: string | undefined,
): string => {
  if (!isAuthenticated) return "Kenni — React (SPA) example";
  return name ? `Welcome ${name}` : "Welcome";
};

export const App = () => {
  const auth = useAuth();

  if (auth.isLoading) {
    return (
      <main className={styles.main}>
        <h1>Loading…</h1>
      </main>
    );
  }

  if (auth.error) {
    return (
      <main className={styles.main}>
        <h1>Sign-in error</h1>
        <pre className={styles.error}>{auth.error.message}</pre>
      </main>
    );
  }

  const profileName = auth.user?.profile.name as string | undefined;

  return (
    <main className={styles.main}>
      <h1>{headingFor(auth.isAuthenticated, profileName)}</h1>
      <PageContainer />
    </main>
  );
};
