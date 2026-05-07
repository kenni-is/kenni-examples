import { Platform, Pressable, ScrollView, StyleSheet, Text, View } from "react-native";

import { useAuth } from "./auth";

// Apple's design makes clean RP-initiated logout impossible on iOS:
// ASWebAuthenticationSession shows a hardcoded "wants to use <domain> to
// sign in" consent prompt, and Safari shows an "Open this page in <App>?"
// prompt when the post-logout redirect hits a custom URL scheme. The only
// real fix is Universal Links (real HTTPS domain + AASA file +
// entitlements), which is too much infrastructure for an example app. So
// on iOS we hide the RP-initiated logout button entirely and lean on
// Sign out (local) + prompt=login on next sign-in. Android Chrome Custom
// Tabs have neither prompt, so the full RP-initiated flow is exposed
// there.
const showRpInitiatedLogout = Platform.OS !== "ios";

const Button = ({
  title,
  onPress,
  disabled,
}: {
  title: string;
  onPress: () => void;
  disabled?: boolean;
}) => (
  <Pressable
    onPress={onPress}
    disabled={disabled}
    style={({ pressed }) => [
      styles.button,
      pressed && styles.buttonPressed,
      disabled && styles.buttonDisabled,
    ]}
  >
    <Text style={styles.buttonText}>{title}</Text>
  </Pressable>
);

export const PageContainer = () => {
  const auth = useAuth();
  const signedIn = auth.isAuthenticated;

  return (
    <View style={styles.container}>
      <View style={styles.buttonStack}>
        {!signedIn && (
          <Button
            title="Continue with Kenni"
            disabled={auth.isLoading || !auth.discovery}
            onPress={() => void auth.signIn()}
          />
        )}

        {signedIn && (
          <>
            <Button
              title={showRpInitiatedLogout ? "Sign out (local)" : "Sign out"}
              onPress={() => void auth.signOutLocal()}
            />
            {showRpInitiatedLogout && (
              <Button
                title="RP-initiated logout"
                onPress={() => void auth.signOutRemote()}
              />
            )}
          </>
        )}
      </View>

      {signedIn && auth.profile && (
        <ScrollView style={styles.details}>
          <Text style={styles.detailsText}>
            {JSON.stringify(auth.profile, null, 2)}
          </Text>
        </ScrollView>
      )}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    width: "100%",
    paddingHorizontal: 24,
    gap: 24,
  },
  buttonStack: {
    gap: 12,
  },
  button: {
    backgroundColor: "#1f2933",
    paddingVertical: 14,
    paddingHorizontal: 18,
    borderRadius: 10,
    alignItems: "center",
  },
  buttonPressed: {
    backgroundColor: "#3a4756",
  },
  buttonDisabled: {
    opacity: 0.5,
  },
  buttonText: {
    color: "white",
    fontSize: 16,
    fontWeight: "600",
  },
  details: {
    maxHeight: 320,
    backgroundColor: "#0b1117",
    borderRadius: 10,
    padding: 14,
  },
  detailsText: {
    color: "#d1d5db",
    fontFamily: "Courier",
    fontSize: 12,
    lineHeight: 18,
  },
});
