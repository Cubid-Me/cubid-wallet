import type { StorybookConfig } from "@storybook/react-vite";
import { mergeConfig } from "vite";
import { nodePolyfills } from "vite-plugin-node-polyfills";

const config: StorybookConfig = {
  stories: ["../src/**/*.mdx", "../src/**/*.stories.@(js|jsx|mjs|ts|tsx)"],
  addons: [
    "@storybook/addon-onboarding",
    "@storybook/addon-links",
    "@storybook/addon-essentials",
    "@chromatic-com/storybook",
    "@storybook/addon-interactions",
  ],
  framework: {
    name: "@storybook/react-vite",
    options: {},
  },
  docs: {
    autodocs: "tag",
  },
  async viteFinal(config) {
    return mergeConfig(config, {
      plugins: [
        nodePolyfills({
          include: [
            'crypto',
            'stream',
            'util',
            'buffer',
            'assert',
            'url',
            'process',
            'http'
          ],
          globals: {
            Buffer: true,
          },
          protocolImports: true, // Critical for Node.js-like protocol handling
        }),
      ],
      define: {
        // Ensure `process.env` is available globally
        'process.env': JSON.stringify({}),
        'process.browser': true,
      },
      resolve: {
        alias: {
          // Force explicit resolution paths
          crypto: 'crypto-browserify',
          stream: 'stream-browserify',
          util: 'util',
          buffer: 'buffer',
           'http':"http",
          process: 'process/browser',
        },
      },
      optimizeDeps: {
        include: [
          // Pre-bundle critical dependencies
          'crypto-browserify',
          'stream-browserify',
          'util',
          'buffer',
          'process',
          'http'
        ],
        esbuildOptions: {
          // Target specific global variables
          define: {
            global: 'globalThis',
          },
        },
      },
    });
  },
};
export default config;
