import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev-server proxy: the dashboard's fetch calls all use relative `/api/...`
// paths (see src/api/client.ts), so in development they're forwarded here
// to `cyberjection serve`'s default `127.0.0.1:8000`. In the production
// container (apps/dashboard/Dockerfile), nginx.conf performs the same
// `/api/` -> backend proxy instead, so the frontend code never needs to
// know which environment it's running in.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
