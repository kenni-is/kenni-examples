import { App } from "./src/App";
import { AuthProvider } from "./src/auth";

export default function Root() {
  return (
    <AuthProvider>
      <App />
    </AuthProvider>
  );
}
