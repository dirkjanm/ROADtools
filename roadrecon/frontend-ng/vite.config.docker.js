import path from 'path'
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import svgLoader from 'vite-svg-loader'

// https://vitejs.dev/config/
export default defineConfig({
  define: {
    'process.env': process.env
  },
  plugins: [vue(), svgLoader()],
  resolve: {
    alias: {
      '@tailwindConfig': path.resolve(__dirname, 'tailwind.config.js'),
    },
  },
  optimizeDeps: {
    include: [
      '@tailwindConfig',
    ]
  },  
  build: {
    commonjsOptions: {
      transformMixedEsModules: true,
    }
  },
  server:{
    host: '0.0.0.0',
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://backend:5000',
        changeOrigin: true,
      },
    },
    fs: {
      allow: [
        '/usr/src/app/node_modules/primeicons/',
        '/usr/src/app/node_modules/vue3-json-viewer/',
        '/usr/src/app/node_modules/vite/dist/client',
        '/usr/src/app/src'
      ]
    }
  }
})
