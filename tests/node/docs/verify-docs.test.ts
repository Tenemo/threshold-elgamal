import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

describe('documentation verification scripts', () => {
    it('keeps verify:docs self-contained while preserving a generated-only entry point', async () => {
        const packageJson = JSON.parse(
            await readFile(
                new URL('../../../package.json', import.meta.url),
                'utf8',
            ),
        ) as {
            scripts?: Record<string, string>;
        };

        expect(packageJson.scripts?.['verify:docs']).toBe(
            'pnpm run docs:api && pnpm run verify:docs:generated',
        );
        expect(packageJson.scripts?.['verify:docs:generated']).toBe(
            'tsx ./typedoc/verify-docs.ts',
        );
        expect(packageJson.scripts?.ci).toContain('pnpm run verify:docs');
    });
});
