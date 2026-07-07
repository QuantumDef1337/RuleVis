import react from '@vitejs/plugin-react';
import { defineConfig } from 'vite';

// Build output goes into the Python package so Flask serves it and
// `pipx install rulevis` ships the UI.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../src/internal/static/dist',
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:5000',
    },
  },
});
