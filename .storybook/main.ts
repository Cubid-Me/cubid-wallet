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
            'stream',
            'util',
            'buffer',
            'assert',
            'url',
            'process',
            'http'
          ],
          exclude: ['crypto'], // Explicitly exclude crypto polyfill
          globals: {
            Buffer: true,
          },
          protocolImports: true,
        }),
      ],
      define: {
        'process.env': JSON.stringify({}),
        'process.browser': true,
      },
      resolve: {
        alias: {
          stream: 'stream-browserify',
          util: 'util',
          buffer: 'buffer',
          'http': "http",
          process: 'process/browser',
        },
      },
      optimizeDeps: {
        include: [
          'stream-browserify',
          'util',
          'buffer',
          'process',
          'http'
        ],
        esbuildOptions: {
          define: {
            global: 'globalThis',
          },
        },
      },
    });
  },
};

export default config;