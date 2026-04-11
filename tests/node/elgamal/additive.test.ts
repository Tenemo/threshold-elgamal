import { describe, expect, it } from 'vitest';

import {
    getGroup,
    InvalidGroupElementError,
    InvalidScalarError,
    PlaintextDomainError,
} from '#core';
import {
    addEncryptedValues,
    assertValidAdditiveCiphertext,
    assertValidFreshAdditiveCiphertext,
    babyStepGiantStep,
    decryptAdditive,
    encryptAdditive,
    encryptAdditiveWithRandomness,
    generateParameters,
    generateParametersWithPrivateKey,
    type ElgamalCiphertext,
} from '#elgamal';
import { encodePoint, multiplyBase } from '#src/core/ristretto';
const additiveIdentity = (): ElgamalCiphertext => {
    const identity = encodePoint(multiplyBase(0n));
    return {
        c1: identity,
        c2: identity,
    } as ElgamalCiphertext;
};
describe('additive ElGamal', () => {
    it('round-trips bounded additive messages', () => {
        const { publicKey, privateKey } = generateParameters();
        for (const message of [0n, 1n, 42n, 1000n]) {
            const ciphertext = encryptAdditive(message, publicKey, 1000n);
            expect(decryptAdditive(ciphertext, privateKey, 1000n)).toBe(
                message,
            );
        }
    });
    it('rejects invalid additive plaintexts and public keys', () => {
        expect.assertions(3);
        const { publicKey } = generateParameters();
        expect(() => encryptAdditive(-1n, publicKey, 10n)).toThrow(
            PlaintextDomainError,
        );
        expect(() => encryptAdditive(11n, publicKey, 10n)).toThrow(
            PlaintextDomainError,
        );
        expect(() => encryptAdditive(1n, 'ff'.repeat(32), 10n)).toThrow(
            InvalidGroupElementError,
        );
    });
    it('rejects additive decryptions that exceed the supplied bound', () => {
        const { publicKey, privateKey } = generateParameters();
        const ciphertext = encryptAdditive(11n, publicKey, 20n);
        expect(() => decryptAdditive(ciphertext, privateKey, 10n)).toThrow(
            PlaintextDomainError,
        );
    });
    it('adds ciphertexts homomorphically', () => {
        const { publicKey, privateKey } = generateParameters();
        const left = encryptAdditive(6n, publicKey, 20n);
        const right = encryptAdditive(7n, publicKey, 20n);
        const sum = addEncryptedValues(left, right);
        expect(decryptAdditive(sum, privateKey, 20n)).toBe(13n);
    });
    it('accepts additive aggregates with identity c1', () => {
        const group = getGroup('ristretto255');
        const { publicKey, privateKey } = generateParametersWithPrivateKey(5n);
        const left = encryptAdditiveWithRandomness(6n, publicKey, 7n, 20n);
        const right = encryptAdditiveWithRandomness(
            7n,
            publicKey,
            group.q - 7n,
            20n,
        );
        const sum = addEncryptedValues(left, right);
        const identity = encodePoint(multiplyBase(0n));
        expect(sum.c1).toBe(identity);
        expect(() => assertValidAdditiveCiphertext(sum)).not.toThrow();
        expect(() => assertValidFreshAdditiveCiphertext(sum)).toThrow(
            InvalidGroupElementError,
        );
        expect(decryptAdditive(sum, privateKey, 20n)).toBe(13n);
    });
    it('accepts additive neutral accumulators', () => {
        const { publicKey, privateKey } = generateParameters();
        const ciphertext = encryptAdditive(11n, publicKey, 20n);
        const sum = addEncryptedValues(additiveIdentity(), ciphertext);
        expect(decryptAdditive(sum, privateKey, 20n)).toBe(11n);
    });
    it('requires an explicit additive bound', () => {
        const { publicKey, privateKey } = generateParameters();
        const ciphertext = encryptAdditive(1n, publicKey, 10n);
        const encryptAdditiveUnchecked = encryptAdditive as (
            ...args: unknown[]
        ) => unknown;
        const decryptAdditiveUnchecked = decryptAdditive as (
            ...args: unknown[]
        ) => unknown;
        expect(() => encryptAdditiveUnchecked(1n, publicKey)).toThrow(
            InvalidScalarError,
        );
        expect(() => decryptAdditiveUnchecked(ciphertext, privateKey)).toThrow(
            InvalidScalarError,
        );
    });
    it('uses canonical ciphertext encodings for the shipped group id', () => {
        const { publicKey, privateKey } =
            generateParametersWithPrivateKey(12345n);
        const expected = encryptAdditiveWithRandomness(
            7n,
            publicKey,
            4100n,
            20n,
        );
        const ciphertext = encryptAdditiveWithRandomness(
            7n,
            publicKey,
            4100n,
            20n,
        );
        expect(ciphertext).toEqual(expected);
        expect(decryptAdditive(ciphertext, privateKey, 20n)).toBe(7n);
    });
    it('is deterministic for fixed randomness and changes when randomness changes', () => {
        const { publicKey } = generateParametersWithPrivateKey(12345n);
        const first = encryptAdditiveWithRandomness(7n, publicKey, 4100n, 20n);
        const same = encryptAdditiveWithRandomness(7n, publicKey, 4100n, 20n);
        const different = encryptAdditiveWithRandomness(
            7n,
            publicKey,
            4101n,
            20n,
        );
        expect(first).toEqual(same);
        expect(different).not.toEqual(first);
    });
    it('rejects invalid deterministic randomness', () => {
        const { publicKey } = generateParameters();
        expect(() =>
            encryptAdditiveWithRandomness(7n, publicKey, 0n, 20n),
        ).toThrow(InvalidScalarError);
    });
    it('returns null when the BSGS search space is too small', () => {
        const group = getGroup('ristretto255');
        const target = encodePoint(multiplyBase(1n));
        expect(babyStepGiantStep(target, group.g, 0n)).toBeNull();
    });
});
