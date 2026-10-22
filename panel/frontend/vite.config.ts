import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The panel backend is proxied so the browser only ever talks to one origin
// (and, in production, only ever to Caddy over HTTPS).
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8080",
      // Subscriptions are served by the panel too; in production Caddy routes
      // them, in dev this keeps `http://127.0.0.1:5173/sub/<id>` working.
      "/sub": "http://127.0.0.1:8080",
    },
  },
});
