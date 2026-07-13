import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Project Aegis frontend — see docs/ARCHITECTURE.md for the full stack overview.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      // Avoids CORS friction in local dev; the backend also has explicit
      // CORS middleware configured in backend/app/main.py as a fallback.
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
