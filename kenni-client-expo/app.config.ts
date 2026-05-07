import type { ExpoConfig } from "expo/config";

// Read the standardized KENNI_* env vars at config time. Expo's CLI
// auto-loads .env (since SDK 49) and exposes anything in process.env to
// app.config.{js,ts}; only EXPO_PUBLIC_-prefixed values reach app code at
// runtime, so we forward what we need through `extra`. This keeps the env
// var names identical to every other example in the repo.
const issuer = process.env.KENNI_ISSUER;
const clientId = process.env.KENNI_CLIENT_ID;
const redirectUri = process.env.KENNI_REDIRECT_URI;
const postLogoutRedirectUri = process.env.KENNI_POST_LOGOUT_REDIRECT_URI;

// The custom URL scheme has to live in the native app config (it ends up
// in Info.plist / AndroidManifest.xml), but it must match the redirect URI
// the developer registers in Kenni. So we derive it from KENNI_REDIRECT_URI
// — one source of truth, no drift.
const schemeFromRedirectUri = (uri: string | undefined): string | undefined => {
  if (!uri) return undefined;
  const match = uri.match(/^([a-zA-Z][a-zA-Z0-9+.-]*):\/\//);
  return match?.[1];
};

const scheme = schemeFromRedirectUri(redirectUri) ?? "is.kenni.expo";

const config: ExpoConfig = {
  name: "kenni-client-expo",
  slug: "kenni-client-expo",
  version: "1.0.0",
  orientation: "portrait",
  icon: "./assets/icon.png",
  userInterfaceStyle: "light",
  scheme,
  splash: {
    image: "./assets/splash.png",
    resizeMode: "contain",
    backgroundColor: "#ffffff",
  },
  assetBundlePatterns: ["**/*"],
  ios: {
    supportsTablet: true,
    bundleIdentifier: "is.kenni.expo",
  },
  android: {
    package: "is.kenni.expo",
    adaptiveIcon: {
      foregroundImage: "./assets/adaptive-icon.png",
      backgroundColor: "#ffffff",
    },
  },
  web: {
    favicon: "./assets/favicon.png",
  },
  plugins: ["expo-secure-store", "expo-web-browser"],
  extra: {
    kenniIssuer: issuer,
    kenniClientId: clientId,
    kenniRedirectUri: redirectUri,
    kenniPostLogoutRedirectUri: postLogoutRedirectUri,
  },
};

export default config;
