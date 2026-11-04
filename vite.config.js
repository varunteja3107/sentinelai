import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      '/api': {
        target: "https" + "://sentinelai-api-2pqw.onrender.com",
        changeOrigin: true,
      },
    },
  },
})
