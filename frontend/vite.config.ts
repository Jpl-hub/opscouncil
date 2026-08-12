import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// https://vite.dev/config/
export default defineConfig({
  plugins: [vue()],
  build: {
    rolldownOptions: {
      output: {
        codeSplitting: {
          groups: [
            {
              name: 'arco-vendor',
              test: /node_modules[\\/]@arco-design[\\/]web-vue/,
              priority: 30,
            },
            {
              name: 'charts-vendor',
              test: /node_modules[\\/](echarts|zrender)[\\/]/,
              priority: 20,
            },
            {
              name: 'vue-vendor',
              test: /node_modules[\\/](@vue|vue|pinia)[\\/]/,
              priority: 10,
            },
            {
              name: 'vendor',
              test: /node_modules/,
              priority: 1,
            },
          ],
        },
      },
    },
  },
  server: {
    proxy: {
      '/api': 'http://127.0.0.1:8000',
      '/mcp': 'http://127.0.0.1:8000',
    },
  },
})
