import { Button, Text, View } from "react-native";
import * as AuthSession from "expo-auth-session";
import * as WebBrowser from "expo-web-browser";

const teamDomain = "some-domain";
const issuer = `https://idp.kenni.is/${teamDomain}`;
const clientId = "some-client-id";

WebBrowser.maybeCompleteAuthSession();
const redirectUri = AuthSession.makeRedirectUri();

export default function App() {
  const discovery = AuthSession.useAutoDiscovery(issuer);
  // Create and load an auth request
  const [request, result, promptAsync] = AuthSession.useAuthRequest(
    {
      clientId,
      redirectUri,
      scopes: ["openid", "profile"],
    },
    discovery
  );

  return (
    <View style={{ flex: 1, justifyContent: "center", alignItems: "center" }}>
      <Button
        title="Login!"
        disabled={!request}
        onPress={() => promptAsync()}
      />
      {result && <Text>{JSON.stringify(result, null, 2)}</Text>}
    </View>
  );
}
