import { describe, expect, it } from 'vitest';

import { getGroup } from '../../src/index';

describe('browser runtime smoke test', () => {
    it('provides browser globals and loads a harmless public import', () => {
        expect(window).toBeDefined();
        expect(crypto.subtle).toBeDefined();
        expect(BigInt(1) + 1n).toBe(2n);

        const group = getGroup();

        expect(group.generator).toBe(2n);
        expect(group.prime > 0n).toBe(true);
    });
});
