import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// P-FIX: compute a unique build hash at config-time so the dashboard
// can self-identify which version is running. Embedded as a build-time
// env var that appears in the topbar.
const BUILD_HASH = (() => {
  const ts = new Date().toISOString().replace(/[:.]/g, '-')
  return `build-${ts}`
})()

export default defineConfig({
  define: {
    'import.meta.env.VITE_BUILD_HASH': JSON.stringify(BUILD_HASH),
  },
  plugins: [react()],
  // P-FREE-recovery: inject __BUILD_HASH__ into index.html so the inline
  // version-check script can compare it against the server-side value
  // returned by /api/v1/system/build.
  plugins: [
    {
      name: 'aegis-build-hash-inject',
      transformIndexHtml(html) {
        // Note: do NOT JSON.stringify — the script wraps it in its own quotes.
        return html.replace(/__BUILD_HASH__/g, () => `"${BUILD_HASH}"`)
      },
    },
    react(),
  ],
  server: {
    port: 3001,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
      },
      '/api/v1/ws': {
        target: 'ws://localhost:8080',
        ws: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    chunkSizeWarningLimit: 600,
    rollupOptions: {
      output: {
        manualChunks: {
          recharts: ['recharts'],
          react: ['react', 'react-dom', 'react-router-dom'],
        },
      },
    },
  },
})
