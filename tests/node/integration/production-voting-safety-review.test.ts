import { readFile } from 'node:fs/promises';

import { describe, expect, it } from 'vitest';

const loadText = async (relativePath: string): Promise<string> =>
    readFile(new URL(`../../../${relativePath}`, import.meta.url), 'utf8');

describe('production voting safety review documentation', () => {
    it('states the production verdict and the explicit non-goals', async () => {
        const review = await loadText(
            'docs/src/content/docs/guides/production-voting-safety-review.md',
        );
        const securityGuide = await loadText(
            'docs/src/content/docs/guides/security-and-non-goals.md',
        );

        expect(review).toContain(
            'Following this implementation `1:1` is not enough to claim production-grade cryptographic safety.',
        );
        expect(review).toContain('| Cast as intended | `not covered` |');
        expect(review).toContain(
            '| Coercion resistance | `explicitly out of scope` |',
        );
        expect(review).toContain(
            '| Receipt-freeness | `explicitly out of scope` |',
        );
        expect(review).toContain(
            '| CCA resistance | `explicitly out of scope` |',
        );
        expect(securityGuide).toContain(
            'It does not provide coercion resistance, receipt-freeness, or cast-as-intended guarantees against a compromised client.',
        );
    });

    it('surfaces the review in the docs index and README', async () => {
        const guidesIndex = await loadText(
            'docs/src/content/docs/guides/index.mdx',
        );
        const readme = await loadText('README.md');

        expect(guidesIndex).toContain('Production voting safety review');
        expect(readme).toContain(
            'Production voting safety review: [tenemo.github.io/threshold-elgamal/guides/production-voting-safety-review]',
        );
    });
});
