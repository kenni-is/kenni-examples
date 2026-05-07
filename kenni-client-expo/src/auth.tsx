import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import {
  exchangeCodeAsync,
  revokeAsync,
  useAuthRequest,
  useAutoDiscovery,
  type DiscoveryDocument,
  type TokenResponse,
} from "expo-auth-session";
import * as WebBrowser from "expo-web-browser";
import * as SecureStore from "expo-secure-store";
import { Linking, Platform } from "react-native";

import {
  clientId,
  issuer,
  postLogoutRedirectUri,
  redirectUri,
  scopes,
} from "./config";
import { decodeJwtPayload } from "./jwt";

// Lets the WebBrowser auth session resolve when the user is bounced back
// into the app via the custom URL scheme.
WebBrowser.maybeCompleteAuthSession();

const TOKENS_KEY = "kenni.tokens.v1";

type StoredTokens = {
  idToken: string;
  accessToken: string;
  refreshToken?: string;
  expiresAt?: number;
};

type AuthState = {
  isLoading: boolean;
  isAuthenticated: boolean;
  isReady: boolean;
  error: string | null;
  profile: Record<string, unknown> | null;
  tokens: StoredTokens | null;
  discovery: DiscoveryDocument | null;
  signIn: () => Promise<void>;
  signOutLocal: () => Promise<void>;
  signOutRemote: () => Promise<void>;
};

const AuthContext = createContext<AuthState | undefined>(undefined);

const tokensFromResponse = (res: TokenResponse): StoredTokens => ({
  idToken: res.idToken ?? "",
  accessToken: res.accessToken,
  refreshToken: res.refreshToken,
  expiresAt:
    res.expiresIn != null ? Date.now() + res.expiresIn * 1000 : undefined,
});

const profileFromIdToken = (
  idToken: string | undefined,
): Record<string, unknown> | null => {
  if (!idToken) return null;
  try {
    return decodeJwtPayload(idToken);
  } catch {
    return null;
  }
};

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const discovery = useAutoDiscovery(issuer);

  const [tokens, setTokens] = useState<StoredTokens | null>(null);
  const [isReady, setIsReady] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // iOS-only: after a local-only sign-out, force the next authorize
  // request to require fresh credentials. RP-initiated logout via
  // ASWebAuthenticationSession on iOS triggers Apple's hardcoded "wants
  // to use kenni.is to sign in" consent prompt, which is unusable as a
  // default sign-out UX. Most iOS users will use Sign out (local), and
  // without prompt=login the next sign-in is silent (Kenni's session
  // cookie in the WebAuthSession cookie jar auto-authenticates them) —
  // making the local sign-out feel fake. prompt=login fixes that.
  const [forceReauth, setForceReauth] = useState(false);

  // Load any persisted session on first mount so a refresh / app relaunch
  // doesn't bounce the user back through Kenni.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const raw = await SecureStore.getItemAsync(TOKENS_KEY);
        if (!cancelled && raw) setTokens(JSON.parse(raw) as StoredTokens);
      } catch {
        // Corrupt entry — ignore and start signed-out.
      } finally {
        if (!cancelled) setIsReady(true);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const persist = useCallback(async (next: StoredTokens | null) => {
    setTokens(next);
    if (next) {
      await SecureStore.setItemAsync(TOKENS_KEY, JSON.stringify(next));
    } else {
      await SecureStore.deleteItemAsync(TOKENS_KEY);
    }
  }, []);

  const [request, , promptAsync] = useAuthRequest(
    {
      clientId,
      redirectUri,
      scopes,
      usePKCE: true,
      extraParams:
        forceReauth && Platform.OS === "ios"
          ? { prompt: "login" }
          : undefined,
    },
    discovery,
  );

  const signIn = useCallback(async () => {
    if (!discovery || !request) {
      setError("Discovery / auth request not ready yet — try again in a moment.");
      return;
    }
    setError(null);
    setIsLoading(true);
    try {
      const result = await promptAsync();
      if (result.type !== "success") {
        if (result.type === "error") setError(result.error?.message ?? "Sign-in failed");
        return;
      }
      const tokenResponse = await exchangeCodeAsync(
        {
          clientId,
          code: result.params.code,
          redirectUri,
          extraParams: request.codeVerifier
            ? { code_verifier: request.codeVerifier }
            : undefined,
        },
        discovery,
      );
      await persist(tokensFromResponse(tokenResponse));
      // Successful sign-in clears the iOS force-reauth flag — the user
      // is now authenticated, future signOutLocal calls will set it
      // again as needed.
      setForceReauth(false);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setIsLoading(false);
    }
  }, [discovery, request, promptAsync, persist]);

  const signOutLocal = useCallback(async () => {
    setError(null);
    await persist(null);
    // iOS only: force the next sign-in to prompt for credentials. See
    // the comment on `forceReauth` above for why.
    if (Platform.OS === "ios") setForceReauth(true);
  }, [persist]);

  const signOutRemote = useCallback(async () => {
    setError(null);
    if (!discovery) {
      setError("Discovery not ready — cannot perform RP-initiated logout.");
      return;
    }

    // Capture the current tokens before clearing local state. We clear
    // first so a failed RP-initiated logout still leaves the local
    // session cleared (per the integration plan).
    const captured = tokens;
    await persist(null);

    if (captured?.refreshToken) {
      try {
        await revokeAsync(
          { token: captured.refreshToken, clientId },
          discovery,
        );
      } catch {
        // Tolerate revocation failure — the cookie clear is what matters
        // for "log this user out everywhere", and that's the next step.
      }
    }

    if (!discovery.endSessionEndpoint) return;

    const url = new URL(discovery.endSessionEndpoint);
    url.searchParams.set("client_id", clientId);
    url.searchParams.set("post_logout_redirect_uri", postLogoutRedirectUri);
    if (captured?.idToken) {
      url.searchParams.set("id_token_hint", captured.idToken);
    }

    try {
      if (Platform.OS === "ios") {
        // iOS: open in Safari via Linking.openURL instead of
        // WebBrowser.openAuthSessionAsync. ASWebAuthenticationSession
        // triggers Apple's "wants to use <domain> to sign in" consent
        // prompt — hardcoded wording, no API to customize — which is
        // nonsensical UX for a sign-out flow. Linking.openURL bypasses
        // it; Safari hits Kenni with its real session cookies, the
        // end-session redirect to is.kenni.expo://post-logout fires
        // the custom-scheme deep link, and iOS bounces back to the app.
        await Linking.openURL(url.toString());
      } else {
        // Android: Chrome Custom Tabs share cookies with Chrome
        // without a consent prompt, so the in-app WebAuthSession is
        // the right primitive — auto-dismisses on the post-logout
        // redirect, no jarring browser switch.
        await WebBrowser.openAuthSessionAsync(
          url.toString(),
          postLogoutRedirectUri,
        );
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [discovery, tokens, persist]);

  const value = useMemo<AuthState>(
    () => ({
      isLoading,
      isReady,
      isAuthenticated: !!tokens?.accessToken,
      error,
      profile: profileFromIdToken(tokens?.idToken),
      tokens,
      discovery: discovery ?? null,
      signIn,
      signOutLocal,
      signOutRemote,
    }),
    [
      isLoading,
      isReady,
      tokens,
      error,
      discovery,
      signIn,
      signOutLocal,
      signOutRemote,
    ],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = (): AuthState => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used inside <AuthProvider>");
  return ctx;
};
