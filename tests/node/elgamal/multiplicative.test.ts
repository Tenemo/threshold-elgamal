import { describe, expect, it } from 'vitest';

import {
    decrypt,
    encrypt,
    generateParameters,
    getGroup,
    InvalidGroupElementError,
    maxVotersForExactProduct,
    multiplyEncryptedValues,
    PlaintextDomainError,
} from '#root';

describe('multiplicative ElGamal', () => {
    it('round-trips across every supported group', () => {
        for (const identifier of [2048, 3072, 4096] as const) {
            const group = getGroup(identifier);
            const { publicKey, privateKey } = generateParameters(group);
            const message = 12345678901234567890n;
            const ciphertext = encrypt(message, publicKey, group);

            expect(decrypt(ciphertext, privateKey, group)).toBe(message);
        }
    });

    it('rejects invalid multiplicative plaintexts', () => {
        const group = getGroup(2048);
        const { publicKey } = generateParameters(group);

        expect(() => encrypt(0n, publicKey, group)).toThrow(
            PlaintextDomainError,
        );
        expect(() => encrypt(-1n, publicKey, group)).toThrow(
            PlaintextDomainError,
        );
        expect(() => encrypt(group.p, publicKey, group)).toThrow(
            PlaintextDomainError,
        );
    });

    it('rejects invalid public keys and ciphertext c1 values', () => {
        const group = getGroup(2048);
        const { publicKey, privateKey } = generateParameters(group);
        const ciphertext = encrypt(7n, publicKey, group);

        expect(() => encrypt(7n, 1n, group)).toThrow(InvalidGroupElementError);
        expect(() =>
            decrypt({ ...ciphertext, c1: group.p - 1n }, privateKey, group),
        ).toThrow(InvalidGroupElementError);
    });

    it('multiplies ciphertexts homomorphically', () => {
        const group = getGroup(2048);
        const { publicKey, privateKey } = generateParameters(group);
        const left = encrypt(6n, publicKey, group);
        const right = encrypt(7n, publicKey, group);

        const product = multiplyEncryptedValues(left, right, group);

        expect(decrypt(product, privateKey, group)).toBe(42n);
    });

    it('computes the exact multiplicative tally bounds', () => {
        expect(maxVotersForExactProduct(10n, getGroup(2048))).toBe(616n);
        expect(maxVotersForExactProduct(10n, getGroup(3072))).toBe(924n);
        expect(maxVotersForExactProduct(10n, getGroup(4096))).toBe(1233n);
    });
});
