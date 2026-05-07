import Constants from "expo-constants";

type Extra = {
  kenniIssuer?: string;
  kenniClientId?: string;
  kenniRedirectUri?: string;
  kenniPostLogoutRedirectUri?: string;
};

const extra = (Constants.expoConfig?.extra ?? {}) as Extra;

const required = (name: keyof Extra, label: string): string => {
  const value = extra[name];
  if (!value) {
    throw new Error(
      `Missing required env var: ${label}. Set it in .env (see .env.example) and restart the bundler so app.config.ts re-reads process.env.`,
    );
  }
  return value;
};

export const issuer = required("kenniIssuer", "KENNI_ISSUER");
export const clientId = required("kenniClientId", "KENNI_CLIENT_ID");
export const redirectUri = required("kenniRedirectUri", "KENNI_REDIRECT_URI");
export const postLogoutRedirectUri = required(
  "kenniPostLogoutRedirectUri",
  "KENNI_POST_LOGOUT_REDIRECT_URI",
);

export const scopes = ["openid", "profile", "national_id", "offline_access"];
