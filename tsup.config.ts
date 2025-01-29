import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  treeshake: true,
  minify: true,
  external: [
    'react',
    'react-dom',
    '@near-wallet-selector/core',
    '@near-wallet-selector/here-wallet',
    '@near-wallet-selector/ledger',
    '@near-wallet-selector/modal-ui',
    '@near-wallet-selector/my-near-wallet',
    '@near-wallet-selector/near-wallet',
    '@near-wallet-selector/sender',
    '@rainbow-me/rainbowkit',
    '@tanstack/react-query',
    'wagmi',
    'near-api-js',
    'cubid-sdk'
  ],
  esbuildOptions(options) {
    options.banner = {
      js: '"use client";',
    }
    // Ensure proper JSX transformation
    options.jsx = 'transform'
    options.jsxFactory = 'React.createElement'
    options.jsxFragment = 'React.Fragment'
  },
  outDir: 'dist'
})