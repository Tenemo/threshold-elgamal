import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

describe('documentation verification scripts', () => {
    it('keeps verify:docs self-contained while preserving a generated-only entry point', async () => {
        const [packageJsonRaw, ciWorkflow, pagesWorkflow, releaseWorkflow] =
            await Promise.all([
                readFile(
                    new URL('../../../package.json', import.meta.url),
                    'utf8',
                ),
                readFile(
                    new URL(
                        '../../../.github/workflows/ci.yml',
                        import.meta.url,
                    ),
                    'utf8',
                ),
                readFile(
                    new URL(
                        '../../../.github/workflows/pages.yml',
                        import.meta.url,
                    ),
                    'utf8',
                ),
                readFile(
                    new URL(
                        '../../../.github/workflows/release.yml',
                        import.meta.url,
                    ),
                    'utf8',
                ),
            ]);
        const packageJson = JSON.parse(packageJsonRaw) as {
            scripts?: Record<string, string>;
        };

        expect(packageJson.scripts?.['verify:docs']).toBe(
            'pnpm run docs:api && pnpm run verify:docs:generated',
        );
        expect(packageJson.scripts?.['verify:docs:generated']).toBe(
            'tsx ./typedoc/verify-docs.ts',
        );
        expect(packageJson.scripts?.ci).toContain('pnpm run verify:docs');
        expect(packageJson.scripts?.ci).toContain('pnpm run docs:build:site');
        expect(packageJson.scripts?.['ci:release-smoke']).toBe(
            'pnpm run ci && pnpm run verify:vectors && pnpm run verify:release-artifacts',
        );
        expect(ciWorkflow).toContain('- run: pnpm run verify:docs');
        expect(ciWorkflow).toContain('- run: pnpm run docs:build:site');
        expect(ciWorkflow).toContain('- run: pnpm run ci:release-smoke');
        expect(ciWorkflow).not.toContain('- run: pnpm run docs:api');
        expect(pagesWorkflow).toContain('- run: pnpm run verify:docs');
        expect(pagesWorkflow).toContain('- run: pnpm run docs:build:site');
        expect(pagesWorkflow).not.toMatch(/^\s*- run: pnpm run docs:build$/m);
        expect(pagesWorkflow.indexOf('pnpm run verify:docs')).toBeLessThan(
            pagesWorkflow.indexOf('pnpm run docs:build:site'),
        );
        expect(releaseWorkflow).toContain('- run: pnpm run ci:release-smoke');
    });
});
