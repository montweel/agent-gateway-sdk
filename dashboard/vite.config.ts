import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  base: '/agent-admin/',
  plugins: [react()],
  build: {
    rolldownOptions: {
      output: {
        // Manual vendor chunks (Vite 8 / Rolldown's replacement for Rollup's `manualChunks`):
        // React, the icon set and the remaining libraries are cached separately from the app
        // code, which changes on every release. Higher priority groups claim modules first.
        codeSplitting: {
          groups: [
            { name: 'react-vendor', test: /[\\/]node_modules[\\/](react|react-dom|scheduler)[\\/]/, priority: 30 },
            { name: 'icons', test: /[\\/]node_modules[\\/]lucide-react[\\/]/, priority: 20 },
            { name: 'vendor', test: /[\\/]node_modules[\\/]/, priority: 10 },
          ],
        },
      },
    },
  },
})
