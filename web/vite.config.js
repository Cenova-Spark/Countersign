import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

export default defineConfig({
  plugins: [vue()],
  server: {
    port: 5180,
    // `vercel dev` serves the functions in api/; point the SPA at it so the
    // browser talks to the same relay routes it will in production.
    proxy: { '/api': { target: 'http://127.0.0.1:3000', changeOrigin: true } },
  },
})
