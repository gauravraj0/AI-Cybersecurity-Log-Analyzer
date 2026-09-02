import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Dev server proxies API + WS to the FastAPI backend so the whole app is
// same-origin. In production the built dist/ is served by FastAPI itself.
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '/api': { target: 'http://localhost:8000', changeOrigin: true },
      '/ws': { target: 'ws://localhost:8000', ws: true },
    },
  },
});
