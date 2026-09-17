import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  base: '/admin/',
  plugins: [react()],
  build: {
    outDir: '../admin/web',
    emptyOutDir: true,
    assetsDir: '',
    sourcemap: false,
    rollupOptions: {
      output: {
        entryFileNames: 'app.js',
        chunkFileNames: '[name].js',
        assetFileNames: (assetInfo) => assetInfo.name?.endsWith('.css') ? 'app.css' : '[name][extname]',
      },
    },
  },
})
