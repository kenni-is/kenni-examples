import { SafeAreaView, StyleSheet, Text, View } from "react-native";
import { StatusBar } from "expo-status-bar";

import { useAuth } from "./auth";
import { PageContainer } from "./PageContainer";

const headingFor = (
  isAuthenticated: boolean,
  name: string | undefined,
): string => {
  if (!isAuthenticated) return "Kenni — Expo example";
  return name ? `Welcome ${name}` : "Welcome";
};

export const App = () => {
  const auth = useAuth();

  if (!auth.isReady) {
    return (
      <SafeAreaView style={styles.screen}>
        <Text style={styles.heading}>Loading…</Text>
        <StatusBar style="auto" />
      </SafeAreaView>
    );
  }

  if (auth.error && !auth.isAuthenticated && !auth.isLoading) {
    return (
      <SafeAreaView style={styles.screen}>
        <Text style={styles.heading}>Sign-in error</Text>
        <View style={styles.errorBox}>
          <Text style={styles.errorText}>{auth.error}</Text>
        </View>
        <PageContainer />
        <StatusBar style="auto" />
      </SafeAreaView>
    );
  }

  const name = auth.profile?.name as string | undefined;

  return (
    <SafeAreaView style={styles.screen}>
      <Text style={styles.heading}>
        {headingFor(auth.isAuthenticated, name)}
      </Text>
      <PageContainer />
      <StatusBar style="auto" />
    </SafeAreaView>
  );
};

const styles = StyleSheet.create({
  screen: {
    flex: 1,
    backgroundColor: "#f4f5f7",
    paddingTop: 48,
    alignItems: "center",
    gap: 24,
  },
  heading: {
    fontSize: 24,
    fontWeight: "700",
    color: "#1f2933",
    paddingHorizontal: 24,
    textAlign: "center",
  },
  errorBox: {
    marginHorizontal: 24,
    padding: 12,
    backgroundColor: "#fde2e2",
    borderRadius: 8,
  },
  errorText: {
    color: "#7a1e1e",
    fontFamily: "Courier",
    fontSize: 12,
  },
});
