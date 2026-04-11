import { fileURLToPath } from 'node:url';

import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

const heavyNodeTestTimeoutMs = 60_000;
const heavyNodeHookTimeoutMs = 240_000;

export default defineConfig({
    resolve: {
        alias: {
            'threshold-elgamal': fileURLToPath(
                new URL('./dist/index.js', import.meta.url),
            ),
        },
    },
    test: {
        coverage: {
            provider: 'v8',
            reporter: ['text', 'json-summary', 'lcov'],
            reportsDirectory: './coverage',
            include: ['src/**/*.ts'],
            exclude: ['src/**/*.d.ts'],
        },
        projects: [
            {
                test: {
                    name: 'node',
                    include: ['tests/node/**/*.test.ts'],
                    environment: 'node',
                    testTimeout: heavyNodeTestTimeoutMs,
                    hookTimeout: heavyNodeHookTimeoutMs,
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
