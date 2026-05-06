import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// We expose env vars prefixed with KENNI_ to client code (instead of Vite's
// default VITE_) so the .env file uses the same KENNI_* names as every other
// example in this repo. Anything that isn't prefixed stays server-only.
export default defineConfig({
  plugins: [react()],
  envPrefix: "KENNI_",
  server: {
    port: 3001,
    strictPort: true,
  },
  preview: {
    port: 3001,
    strictPort: true,
  },
});
