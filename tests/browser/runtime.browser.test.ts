import { describe, expect, it } from 'vitest';

import {
    decryptAdditive,
    encryptAdditive,
    generateParameters,
    getGroup,
} from '#root';

describe('browser runtime smoke test', () => {
    it('provides browser globals and performs a v2 round-trip', () => {
        expect(window).toBeDefined();
        expect(crypto.subtle).toBeDefined();
        expect(BigInt(1) + 1n).toBe(2n);

        const group = 2048 as const;
        const suite = getGroup(group);
        const { publicKey, privateKey } = generateParameters(group);
        const ciphertext = encryptAdditive(9n, publicKey, group, 20n);

        expect(suite.g).toBe(2n);
        expect(suite.h > 1n).toBe(true);
        expect(suite.p > 0n).toBe(true);
        expect(suite.q > 0n).toBe(true);
        expect(decryptAdditive(ciphertext, privateKey, group, 20n)).toBe(9n);
    });
});
