import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'vitest/config';

const rootDir = dirname(fileURLToPath(import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@nuverther/zk': resolve(rootDir, 'packages/zk/src/index.ts'),
      '@nuverther/node': resolve(rootDir, 'packages/node/src/index.ts'),
      '@nuverther/client': resolve(rootDir, 'packages/client/src/index.ts'),
    },
  },
  test: {
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    testTimeout: 120_000,
    hookTimeout: 120_000,
  },
});
