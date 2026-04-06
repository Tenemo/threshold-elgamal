import { describe, expect, it } from 'vitest';

import plainElgamalVectors from '../../../test-vectors/plain-elgamal.json';

import {
    generateParameters,
    getGroup,
    InvalidGroupElementError,
    InvalidScalarError,
    PlaintextDomainError,
    UnsupportedSuiteError,
} from '#root';
import {
    assertValidFreshMultiplicativeCiphertext,
    assertValidMultiplicativeCiphertext,
    decrypt,
    encrypt,
    encryptWithRandomness,
    generateParametersWithPrivateKey,
    maxVotersForExactProduct,
    multiplyEncryptedValues,
} from '#unsafe';

describe('unsafe multiplicative ElGamal', () => {
    it('round-trips across every supported group', () => {
        for (const identifier of [2048, 3072, 4096] as const) {
            const { publicKey, privateKey } = generateParameters(identifier);
            const message = 12345678901234567890n;
            const ciphertext = encrypt(message, publicKey, identifier);

            expect(decrypt(ciphertext, privateKey, identifier)).toBe(message);
        }
    });

    it('rejects invalid multiplicative plaintexts', () => {
        const { publicKey } = generateParameters(2048);
        const group = getGroup(2048);

        expect(() => encrypt(0n, publicKey, 2048)).toThrow(
            PlaintextDomainError,
        );
        expect(() => encrypt(-1n, publicKey, 2048)).toThrow(
            PlaintextDomainError,
        );
        expect(() => encrypt(group.p, publicKey, 2048)).toThrow(
            PlaintextDomainError,
        );
    });

    it('rejects invalid public keys and ciphertext c1 values', () => {
        const group = getGroup(2048);
        const { publicKey, privateKey } = generateParameters(2048);
        const ciphertext = encrypt(7n, publicKey, 2048);

        expect(() => encrypt(7n, 1n, 2048)).toThrow(InvalidGroupElementError);
        expect(() =>
            decrypt({ ...ciphertext, c1: group.p - 1n }, privateKey, 2048),
        ).toThrow(InvalidGroupElementError);
    });

    it('multiplies ciphertexts homomorphically', () => {
        const { publicKey, privateKey } = generateParameters(2048);
        const left = encrypt(6n, publicKey, 2048);
        const right = encrypt(7n, publicKey, 2048);

        const product = multiplyEncryptedValues(left, right, 2048);

        expect(decrypt(product, privateKey, 2048)).toBe(42n);
    });

    it('accepts multiplicative aggregates with subgroup identity in c1', () => {
        const group = getGroup(2048);
        const { publicKey, privateKey } = generateParametersWithPrivateKey(
            5n,
            2048,
        );
        const left = encryptWithRandomness(6n, publicKey, 7n, 2048);
        const right = encryptWithRandomness(7n, publicKey, group.q - 7n, 2048);

        const product = multiplyEncryptedValues(left, right, 2048);

        expect(product.c1).toBe(1n);
        expect(() =>
            assertValidMultiplicativeCiphertext(product, group),
        ).not.toThrow();
        expect(() =>
            assertValidFreshMultiplicativeCiphertext(product, group),
        ).toThrow(InvalidGroupElementError);
        expect(decrypt(product, privateKey, 2048)).toBe(42n);
    });

    it('accepts multiplicative neutral accumulators', () => {
        const { publicKey, privateKey } = generateParameters(2048);
        const ciphertext = encrypt(11n, publicKey, 2048);
        const product = multiplyEncryptedValues(
            { c1: 1n, c2: 1n },
            ciphertext,
            2048,
        );

        expect(decrypt(product, privateKey, 2048)).toBe(11n);
    });

    it('rejects arbitrary group objects at runtime', () => {
        const group = getGroup(2048);
        const { publicKey } = generateParameters(2048);

        expect(() => encrypt(7n, publicKey, group as never)).toThrow(
            UnsupportedSuiteError,
        );
    });

    it('rejects invalid deterministic randomness', () => {
        const { publicKey } = generateParameters(2048);

        expect(() => encryptWithRandomness(7n, publicKey, 0n, 2048)).toThrow(
            InvalidScalarError,
        );
    });

    it('computes the exact multiplicative tally bounds', () => {
        expect(maxVotersForExactProduct(10n, 2048)).toBe(616n);
        expect(maxVotersForExactProduct(10n, 3072)).toBe(924n);
        expect(maxVotersForExactProduct(10n, 4096)).toBe(1233n);
    });

    it('matches the frozen multiplicative vectors for every shipped group', () => {
        for (const [groupName, vector] of Object.entries(
            plainElgamalVectors.groups,
        )) {
            const group = getGroup(groupName as never);
            const multiplicativeVector = vector.multiplicative;
            const keyPair = generateParametersWithPrivateKey(
                BigInt(vector.privateKey),
                group.name,
            );
            const ciphertext = encryptWithRandomness(
                BigInt(multiplicativeVector.message),
                keyPair.publicKey,
                BigInt(multiplicativeVector.randomness),
                group.name,
            );

            expect(keyPair.publicKey).toBe(BigInt(vector.publicKey));
            expect(ciphertext).toEqual({
                c1: BigInt(multiplicativeVector.c1),
                c2: BigInt(multiplicativeVector.c2),
            });
            expect(decrypt(ciphertext, keyPair.privateKey, group.name)).toBe(
                BigInt(multiplicativeVector.message),
            );
        }
    });

    it('matches the frozen multiplicative homomorphic vectors', () => {
        for (const [groupName, vector] of Object.entries(
            plainElgamalVectors.groups,
        )) {
            const group = getGroup(groupName as never);
            const keyPair = generateParametersWithPrivateKey(
                BigInt(vector.privateKey),
                group.name,
            );
            const left = encryptWithRandomness(
                BigInt(vector.multiplicative.left.message),
                keyPair.publicKey,
                BigInt(vector.multiplicative.left.randomness),
                group.name,
            );
            const right = encryptWithRandomness(
                BigInt(vector.multiplicative.right.message),
                keyPair.publicKey,
                BigInt(vector.multiplicative.right.randomness),
                group.name,
            );
            const product = multiplyEncryptedValues(left, right, group.name);

            expect(product).toEqual({
                c1: BigInt(vector.multiplicative.product.c1),
                c2: BigInt(vector.multiplicative.product.c2),
            });
            expect(decrypt(product, keyPair.privateKey, group.name)).toBe(
                BigInt(vector.multiplicative.product.message),
            );
        }
    });
});
