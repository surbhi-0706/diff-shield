import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  // Extension pages are loaded from the extension directory, not a web server root.
  base: './',
})
