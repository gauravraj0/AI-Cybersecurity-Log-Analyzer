import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const proxy = {
  "/api": {
    target: process.env.API_PROXY || "http://127.0.0.1:8000",
    changeOrigin: true,
  },
};

export default defineConfig({
  plugins: [react()],
  server: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,
    allowedHosts: true,
    hmr: false,
    proxy,
    headers: {
      "Cache-Control": "no-store",
    },
  },
  preview: {
    host: "0.0.0.0",
    port: 5173,
    strictPort: true,
    allowedHosts: true,
    proxy,
    headers: {
      "Cache-Control": "no-store",
    },
  },
});
