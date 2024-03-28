import { useState } from "react";
import { Button, SafeAreaView, Text } from "react-native";
import {
  exchangeCodeAsync,
  makeRedirectUri,
  useAuthRequest,
  useAutoDiscovery,
} from "expo-auth-session";
import * as WebBrowser from "expo-web-browser";
import * as SecureStore from "expo-secure-store";
import { Buffer } from "buffer";

const issuer = process.env.EXPO_PUBLIC_ISSUER as string;
const clientId = process.env.EXPO_PUBLIC_CLIENT_ID as string;

WebBrowser.maybeCompleteAuthSession();

export default function App() {
  const discovery = useAutoDiscovery(issuer);
  const redirectUri = makeRedirectUri({
    scheme: undefined,
    path: "callback",
  });

  // We store the JWT in here
  const [error, setError] = useState<string | null>(null);
  const [isAuthenticating, setIsAuthenticating] = useState(false);
  const [user, setUser] = useState<string | null>(SecureStore.getItem("user"));

  // Request
  const [request, , promptAsync] = useAuthRequest(
    {
      clientId,
      scopes: ["openid", "profile"],
      redirectUri,
    },
    discovery
  );

  return (
    <SafeAreaView
      style={{ flex: 1, justifyContent: "center", alignItems: "center" }}
    >
      {user ? (
        <Button
          title="Log out"
          onPress={() => {
            SecureStore.deleteItemAsync("user");
            setUser(null);
          }}
        />
      ) : (
        <Button
          disabled={isAuthenticating}
          title="Login"
          onPress={async () => {
            setIsAuthenticating(true);
            const codeResponse = await promptAsync();
            if (!request || codeResponse?.type !== "success" || !discovery) {
              setIsAuthenticating(false);
              setError("Something went wrong during authorization...");
              return;
            }

            const res = await exchangeCodeAsync(
              {
                clientId,
                code: codeResponse.params.code,
                extraParams: request.codeVerifier
                  ? { code_verifier: request.codeVerifier }
                  : undefined,
                redirectUri,
              },
              discovery
            );

            const idToken = res?.idToken;
            if (!idToken) {
              setIsAuthenticating(false);
              setError("Something went wrong during code exchange...");
              return;
            }

            const payload = idToken.split(".")[1];
            const userString = Buffer.from(payload, "base64").toString("ascii");

            const userFromToken = userString;
            await SecureStore.setItemAsync("user", userFromToken);

            setUser(userFromToken);
            setIsAuthenticating(false);
          }}
        />
      )}
      {error && <Text>{error}</Text>}
      {user && <Text>{user}</Text>}
    </SafeAreaView>
  );
}
