import { WebStorageStateStore } from "oidc-client-ts";
import type { AuthProviderProps } from "react-oidc-context";

const required = (name: keyof ImportMetaEnv): string => {
  const value = import.meta.env[name];
  if (!value) throw new Error(`Missing required env var: ${name}`);
  return value;
};

export const clientId = required("KENNI_CLIENT_ID");

export const oidcConfig: AuthProviderProps = {
  authority: required("KENNI_ISSUER"),
  client_id: clientId,
  redirect_uri: required("KENNI_REDIRECT_URI"),
  post_logout_redirect_uri: required("KENNI_POST_LOGOUT_REDIRECT_URI"),
  response_type: "code",
  scope: "openid profile national_id offline_access",
  // Persist the user across reloads so a refresh doesn't bounce the user
  // back through Kenni. Default is sessionStorage; localStorage survives
  // tab close. Pick whichever fits your app's session model.
  userStore: new WebStorageStateStore({ store: window.localStorage }),
  // After the code-exchange completes on /callback, strip the auth-response
  // query string so the URL is clean if the user shares it.
  onSigninCallback: () => {
    window.history.replaceState({}, document.title, window.location.pathname);
  },
};
