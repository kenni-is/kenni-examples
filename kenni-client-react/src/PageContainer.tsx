import { useAuth } from "react-oidc-context";

import { clientId } from "./oidc-config";
import styles from "./PageContainer.module.css";

export const PageContainer = () => {
  const auth = useAuth();
  const signedIn = auth.isAuthenticated;

  return (
    <>
      <div className={styles.buttonStack}>
        {!signedIn && (
          <button onClick={() => void auth.signinRedirect()}>
            Continue with Kenni
          </button>
        )}

        {signedIn && (
          <>
            <button onClick={() => void auth.removeUser()}>
              Sign out (local)
            </button>
            <button
              onClick={() =>
                void auth.signoutRedirect({
                  // Kenni requires `client_id` on the end-session request
                  // when an `id_token_hint` is sent. oidc-client-ts doesn't
                  // add it automatically, so we forward it via
                  // extraQueryParams. id_token_hint and
                  // post_logout_redirect_uri are added by the library.
                  extraQueryParams: { client_id: clientId },
                })
              }
            >
              RP-initiated logout
            </button>
          </>
        )}
      </div>

      {signedIn && auth.user && (
        <pre className={styles.details}>
          {JSON.stringify(auth.user.profile, null, 2)}
        </pre>
      )}
    </>
  );
};
