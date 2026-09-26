import { defineConfig, loadEnv, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'

function verifyAdminBundle(): Plugin {
  return {
    name: 'verify-admin-bundle',
    generateBundle(_options, bundle) {
      const initialChunks: string[] = []
      for (const output of Object.values(bundle)) {
        if (output.type !== 'chunk') continue
        if (new TextEncoder().encode(output.code).length > 500 * 1024) {
          this.error(`Admin JavaScript chunk exceeds 500 KiB: ${output.fileName}`)
        }
        if (output.isEntry) initialChunks.push(output.fileName)
      }
      const visited = new Set<string>()
      while (initialChunks.length) {
        const name = initialChunks.pop()!
        if (visited.has(name)) continue
        visited.add(name)
        const chunk = bundle[name]
        if (!chunk || chunk.type !== 'chunk') continue
        if (chunk.moduleIds.some((id) => /\/node_modules\/(?:@xyflow|@dagrejs)\//.test(id.replaceAll('\\', '/')))) {
          this.error(`Graph libraries must load on demand, but ${name} is an initial dependency`)
        }
        initialChunks.push(...chunk.imports)
      }
    },
  }
}

export default defineConfig(({ mode }) => ({
  base: '/admin/',
  plugins: [
    react(),
    verifyAdminBundle(),
    {
      name: 'admin-base-redirect',
      configureServer(server) {
        server.middlewares.use((req, res, next) => {
          const requestUrl = req.url || ''
          if (requestUrl === '/admin' || requestUrl.startsWith('/admin?')) {
            res.statusCode = 302
            res.setHeader('Location', `/admin/${requestUrl.slice('/admin'.length)}`)
            res.end()
            return
          }
          next()
        })
      },
    },
  ],
  server: {
    proxy: {
      '/admin/api/v1': { target: loadEnv(mode, '.', '').ADMIN_API_ORIGIN || 'http://127.0.0.1:18080', changeOrigin: false },
    },
  },
  build: {
    outDir: '../admin/web',
    emptyOutDir: true,
    assetsDir: '',
    sourcemap: false,
    cssCodeSplit: false,
    rollupOptions: {
      output: {
        manualChunks(id) {
          const moduleId = id.replaceAll('\\', '/')
          if (!moduleId.includes('/node_modules/')) return undefined

          if (
            moduleId.includes('/node_modules/@xyflow/') ||
            moduleId.includes('/node_modules/@dagrejs/') ||
            moduleId.includes('/node_modules/d3-') ||
            moduleId.includes('/node_modules/zustand/') ||
            moduleId.includes('/node_modules/classcat/')
          ) return 'graph-vendor'

          if (moduleId.includes('/node_modules/@tanstack/')) return 'data-vendor'

          if (
            moduleId.includes('/node_modules/react/') ||
            moduleId.includes('/node_modules/react-dom/') ||
            moduleId.includes('/node_modules/react-router/') ||
            moduleId.includes('/node_modules/react-router-dom/') ||
            moduleId.includes('/node_modules/scheduler/')
          ) return 'react-vendor'

          return undefined
        },
        entryFileNames: 'app.js',
        chunkFileNames: '[name].js',
        assetFileNames: (assetInfo) => assetInfo.name?.endsWith('.css') ? 'app.css' : '[name][extname]',
      },
    },
  },
}))
