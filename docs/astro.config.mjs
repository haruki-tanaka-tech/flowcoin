import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://flowcoin.org',
  build: {
    inlineStylesheets: 'auto',
  },
  compressHTML: true,
});
