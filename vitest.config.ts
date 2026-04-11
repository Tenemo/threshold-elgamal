import { playwright } from '@vitest/browser-playwright';
import { defineConfig } from 'vitest/config';

const nodeTestTimeoutMs = 60_000;
const nodeHookTimeoutMs = 240_000;

const nodeProject = {
    environment: 'node',
    testTimeout: nodeTestTimeoutMs,
    hookTimeout: nodeHookTimeoutMs,
} as const;

export default defineConfig({
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
                    ...nodeProject,
                },
            },
            {
                test: {
                    name: 'node-fast',
                    include: ['tests/node/**/*.test.ts'],
                    exclude: ['tests/node/integration/**/*.test.ts'],
                    ...nodeProject,
                },
            },
            {
                test: {
                    name: 'node-heavy',
                    include: ['tests/node/integration/**/*.test.ts'],
                    ...nodeProject,
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
