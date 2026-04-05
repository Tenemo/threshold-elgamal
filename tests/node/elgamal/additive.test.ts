import { describe, expect, it } from 'vitest';

import { encryptAdditiveWithRandomness } from '../../../src/elgamal/additive.js';
import { generateParametersWithPrivateKey } from '../../../src/elgamal/multiplicative.js';

import {
    addEncryptedValues,
    assertValidAdditiveCiphertext,
    assertValidFreshAdditiveCiphertext,
    babyStepGiantStep,
    decryptAdditive,
    encryptAdditive,
    generateParameters,
    getGroup,
    InvalidGroupElementError,
    InvalidScalarError,
    PlaintextDomainError,
    UnsupportedSuiteError,
} from '#root';

describe('additive ElGamal', () => {
    it('round-trips bounded additive messages', () => {
        const { publicKey, privateKey } = generateParameters(2048);

        for (const message of [0n, 1n, 42n, 1000n]) {
            const ciphertext = encryptAdditive(message, publicKey, 2048, 1000n);
            expect(decryptAdditive(ciphertext, privateKey, 2048, 1000n)).toBe(
                message,
            );
        }
    });

    it('rejects invalid additive plaintexts and public keys', () => {
        expect.assertions(3);

        const { publicKey } = generateParameters(2048);

        expect(() => encryptAdditive(-1n, publicKey, 2048, 10n)).toThrow(
            PlaintextDomainError,
        );
        expect(() => encryptAdditive(11n, publicKey, 2048, 10n)).toThrow(
            PlaintextDomainError,
        );
        expect(() => encryptAdditive(1n, 1n, 2048, 10n)).toThrow(
            InvalidGroupElementError,
        );
    });

    it('rejects additive decryptions that exceed the supplied bound', () => {
        const { publicKey, privateKey } = generateParameters(2048);
        const ciphertext = encryptAdditive(11n, publicKey, 2048, 20n);

        expect(() =>
            decryptAdditive(ciphertext, privateKey, 2048, 10n),
        ).toThrow(PlaintextDomainError);
    });

    it('adds ciphertexts homomorphically', () => {
        const { publicKey, privateKey } = generateParameters(2048);
        const left = encryptAdditive(6n, publicKey, 2048, 20n);
        const right = encryptAdditive(7n, publicKey, 2048, 20n);

        const sum = addEncryptedValues(left, right, 2048);

        expect(decryptAdditive(sum, privateKey, 2048, 20n)).toBe(13n);
    });

    it('accepts additive aggregates with subgroup identity in c1', () => {
        const group = getGroup(2048);
        const { publicKey, privateKey } = generateParametersWithPrivateKey(
            5n,
            2048,
        );
        const left = encryptAdditiveWithRandomness(
            6n,
            publicKey,
            7n,
            20n,
            2048,
        );
        const right = encryptAdditiveWithRandomness(
            7n,
            publicKey,
            group.q - 7n,
            20n,
            2048,
        );

        const sum = addEncryptedValues(left, right, 2048);

        expect(sum.c1).toBe(1n);
        expect(() => assertValidAdditiveCiphertext(sum, group)).not.toThrow();
        expect(() => assertValidFreshAdditiveCiphertext(sum, group)).toThrow(
            InvalidGroupElementError,
        );
        expect(decryptAdditive(sum, privateKey, 2048, 20n)).toBe(13n);
    });

    it('accepts additive neutral accumulators', () => {
        const { publicKey, privateKey } = generateParameters(2048);
        const ciphertext = encryptAdditive(11n, publicKey, 2048, 20n);
        const sum = addEncryptedValues({ c1: 1n, c2: 1n }, ciphertext, 2048);

        expect(decryptAdditive(sum, privateKey, 2048, 20n)).toBe(11n);
    });

    it('requires an explicit additive bound', () => {
        const { publicKey, privateKey } = generateParameters(2048);
        const ciphertext = encryptAdditive(1n, publicKey, 2048, 10n);

        expect(() => encryptAdditive(1n, publicKey, 2048 as never)).toThrow(
            InvalidScalarError,
        );
        expect(() =>
            decryptAdditive(ciphertext, privateKey, 2048 as never),
        ).toThrow(InvalidScalarError);
    });

    it('rejects arbitrary group objects at runtime', () => {
        const group = getGroup(2048);
        const { publicKey } = generateParameters(2048);

        expect(() =>
            encryptAdditive(7n, publicKey, group as never, 10n),
        ).toThrow(UnsupportedSuiteError);
    });

    it('rejects invalid deterministic randomness', () => {
        const { publicKey } = generateParameters(2048);

        expect(() =>
            encryptAdditiveWithRandomness(7n, publicKey, 0n, 20n, 2048),
        ).toThrow(InvalidScalarError);
    });

    it('returns null when BSGS search space is too small', () => {
        const group = getGroup(2048);
        const encoded = group.g ** 0n;
        const target = (encoded * group.g) % group.p;

        expect(babyStepGiantStep(target, group.g, group.p, 0n)).toBeNull();
    });
});
