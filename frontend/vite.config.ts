import { fileURLToPath, URL } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Project Aegis frontend — see docs/ARCHITECTURE.md for the full stack overview.
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      // The "@/..." path alias is declared in tsconfig.json, but that only
      // teaches tsc how to type-check it. Rollup resolves imports itself, so
      // the same alias has to be declared here or `vite build` fails to
      // resolve every "@/components/..." import.
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  server: {
    port: 5173,
    proxy: {
      // Avoids CORS friction in local dev; the backend also has explicit
      // CORS middleware configured in backend/app/main.py as a fallback.
      // In the container the same "/api" prefix is proxied by nginx instead
      // (see frontend/nginx.conf).
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  test: {
    environment: "jsdom",
    globals: true,
    setupFiles: ["./src/test/setup.ts"],
    css: false,
  },
});
