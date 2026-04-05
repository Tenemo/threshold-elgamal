import { describe, expect, it } from 'vitest';

import {
    decrypt,
    encrypt,
    generateParameters,
    getGroup,
} from '../../src/index';

describe('browser runtime smoke test', () => {
    it('provides browser globals and performs a v2 round-trip', () => {
        expect(window).toBeDefined();
        expect(crypto.subtle).toBeDefined();
        expect(BigInt(1) + 1n).toBe(2n);

        const group = getGroup(2048);
        const { publicKey, privateKey } = generateParameters(group);
        const ciphertext = encrypt(9n, publicKey, group);

        expect(group.g).toBe(2n);
        expect(group.h > 1n).toBe(true);
        expect(group.p > 0n).toBe(true);
        expect(group.q > 0n).toBe(true);
        expect(decrypt(ciphertext, privateKey, group)).toBe(9n);
    });
});
