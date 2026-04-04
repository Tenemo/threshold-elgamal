import { describe, expect, it } from 'vitest';

import { getGroup } from '../../src/core';

describe('browser runtime smoke test', () => {
    it('provides browser globals and loads a harmless public import', () => {
        expect(window).toBeDefined();
        expect(crypto.subtle).toBeDefined();
        expect(BigInt(1) + 1n).toBe(2n);

        const group = getGroup();

        expect(group.g).toBe(2n);
        expect(group.h > 1n).toBe(true);
        expect(group.p > 0n).toBe(true);
        expect(group.q > 0n).toBe(true);
    });
});
