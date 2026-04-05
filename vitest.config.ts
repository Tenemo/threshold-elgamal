import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

const rootDir = fileURLToPath(new URL('.', import.meta.url));

export default defineConfig({
    resolve: {
        alias: {
            'threshold-elgamal': path.resolve(rootDir, 'src/index.ts'),
            'threshold-elgamal/core': path.resolve(
                rootDir,
                'src/core/index.ts',
            ),
            'threshold-elgamal/elgamal': path.resolve(
                rootDir,
                'src/elgamal/index.ts',
            ),
            'threshold-elgamal/serialize': path.resolve(
                rootDir,
                'src/serialize/index.ts',
            ),
        },
    },
    test: {
        projects: [
            {
                test: {
                    name: 'node',
                    include: ['tests/node/**/*.test.ts'],
                    environment: 'node',
                },
            },
            {
                test: {
                    name: 'browser',
                    include: ['tests/browser/**/*.browser.test.ts'],
                    browser: {
                        enabled: true,
                        provider: playwright(),
                        headless: true,
                        instances: [{ browser: 'chromium' }],
                    },
                },
            },
        ],
    },
});
