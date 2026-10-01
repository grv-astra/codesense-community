/// <reference types="vitest/config" />
import path from "path"
import tailwindcss from "@tailwindcss/vite"
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react-swc'
import { tanstackRouter } from '@tanstack/router-plugin/vite'
import { visualizer } from 'rollup-plugin-visualizer'

// Vendor code that IS in the eager path is split into stable, independently-
// cacheable chunks so an app-code edit doesn't bust the (large, rarely-changing)
// framework bundles. Anything not matched here stays with the route/entry chunk
// that imports it — in particular recharts + d3, which only the dashboard reaches
// (via React.lazy): left unlisted, Rollup keeps it in the dashboard's async
// chunk graph so it never touches first load. Forcing it into a named "vendor"
// chunk here would instead hoist it into the entry's eager modulepreload set.
const VENDOR_CHUNKS: Record<string, RegExp> = {
  'vendor-react': /[/\\]node_modules[/\\](react|react-dom|scheduler|use-sync-external-store)[/\\]/,
  'vendor-tanstack': /[/\\]node_modules[/\\]@tanstack[/\\]/,
  'vendor-radix': /[/\\]node_modules[/\\]@radix-ui[/\\]/,
  'vendor-http': /[/\\]node_modules[/\\](axios|follow-redirects)[/\\]/,
  'vendor-icons': /[/\\]node_modules[/\\]lucide-react[/\\]/,
}

// https://vite.dev/config/
export default defineConfig({
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./src/test/setup.ts'],
  },
  server: {
    host: true,
    // A Tauri build stages ~18 MB of Semgrep rule fixtures (*.html with example
    // vulnerable code) under src-tauri/target/. Left to its own devices, the dep
    // scanner treats every one as an entry, trips over an unresolved
    // `@google/generative-ai` import inside a fixture, and then thrashes the
    // optimizer (repeated re-optimize -> 504 Outdated Optimize Dep -> duplicate
    // React copies). Don't watch that tree.
    watch: {
      ignored: ['**/src-tauri/target/**'],
    },
  },
  preview: {
    host: true,
  },
  // Pin dep pre-bundling to the real app entry so the scanner never wanders into
  // src-tauri/target/ (see server.watch.ignored above).
  optimizeDeps: {
    entries: ['index.html'],
  },
  plugins: [
    tanstackRouter({
      target: 'react',
      autoCodeSplitting: true,
    }),
    react(),
    tailwindcss(),
    // Writes dist/stats.html on every build — open it to see the chunk treemap.
    visualizer({
      filename: 'dist/stats.html',
      gzipSize: true,
      brotliSize: true,
    }),
  ],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          for (const [chunk, pattern] of Object.entries(VENDOR_CHUNKS)) {
            if (pattern.test(id)) return chunk
          }
        },
      },
    },
  },
})
