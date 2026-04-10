import { describe, expect, it } from 'vitest';

import type { ElgamalCiphertext } from '#elgamal';
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
    getGroup,
    InvalidGroupElementError,
    InvalidScalarError,
    PlaintextDomainError,
    UnsupportedSuiteError,
} from '#root';
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
        const { publicKey, privateKey } = generateParameters('ristretto255');

        for (const message of [0n, 1n, 42n, 1000n]) {
            const ciphertext = encryptAdditive(
                message,
                publicKey,
                'ristretto255',
                1000n,
            );
            expect(
                decryptAdditive(ciphertext, privateKey, 'ristretto255', 1000n),
            ).toBe(message);
        }
    });

    it('rejects invalid additive plaintexts and public keys', () => {
        expect.assertions(3);

        const { publicKey } = generateParameters('ristretto255');

        expect(() =>
            encryptAdditive(-1n, publicKey, 'ristretto255', 10n),
        ).toThrow(PlaintextDomainError);
        expect(() =>
            encryptAdditive(11n, publicKey, 'ristretto255', 10n),
        ).toThrow(PlaintextDomainError);
        expect(() =>
            encryptAdditive(1n, 'ff'.repeat(32), 'ristretto255', 10n),
        ).toThrow(InvalidGroupElementError);
    });

    it('rejects additive decryptions that exceed the supplied bound', () => {
        const { publicKey, privateKey } = generateParameters('ristretto255');
        const ciphertext = encryptAdditive(11n, publicKey, 'ristretto255', 20n);

        expect(() =>
            decryptAdditive(ciphertext, privateKey, 'ristretto255', 10n),
        ).toThrow(PlaintextDomainError);
    });

    it('adds ciphertexts homomorphically', () => {
        const { publicKey, privateKey } = generateParameters('ristretto255');
        const left = encryptAdditive(6n, publicKey, 'ristretto255', 20n);
        const right = encryptAdditive(7n, publicKey, 'ristretto255', 20n);

        const sum = addEncryptedValues(left, right, 'ristretto255');

        expect(decryptAdditive(sum, privateKey, 'ristretto255', 20n)).toBe(13n);
    });

    it('accepts additive aggregates with identity c1', () => {
        const group = getGroup('ristretto255');
        const { publicKey, privateKey } = generateParametersWithPrivateKey(
            5n,
            'ristretto255',
        );
        const left = encryptAdditiveWithRandomness(
            6n,
            publicKey,
            7n,
            20n,
            group.name,
        );
        const right = encryptAdditiveWithRandomness(
            7n,
            publicKey,
            group.q - 7n,
            20n,
            group.name,
        );

        const sum = addEncryptedValues(left, right, group.name);
        const identity = encodePoint(multiplyBase(0n));

        expect(sum.c1).toBe(identity);
        expect(() => assertValidAdditiveCiphertext(sum, group)).not.toThrow();
        expect(() => assertValidFreshAdditiveCiphertext(sum, group)).toThrow(
            InvalidGroupElementError,
        );
        expect(decryptAdditive(sum, privateKey, group.name, 20n)).toBe(13n);
    });

    it('accepts additive neutral accumulators', () => {
        const { publicKey, privateKey } = generateParameters('ristretto255');
        const ciphertext = encryptAdditive(11n, publicKey, 'ristretto255', 20n);
        const sum = addEncryptedValues(
            additiveIdentity(),
            ciphertext,
            'ristretto255',
        );

        expect(decryptAdditive(sum, privateKey, 'ristretto255', 20n)).toBe(11n);
    });

    it('requires an explicit additive bound', () => {
        const { publicKey, privateKey } = generateParameters('ristretto255');
        const ciphertext = encryptAdditive(1n, publicKey, 'ristretto255', 10n);
        const encryptAdditiveUnchecked = encryptAdditive as (
            ...args: unknown[]
        ) => unknown;
        const decryptAdditiveUnchecked = decryptAdditive as (
            ...args: unknown[]
        ) => unknown;

        expect(() =>
            encryptAdditiveUnchecked(1n, publicKey, 'ristretto255'),
        ).toThrow(InvalidScalarError);
        expect(() =>
            decryptAdditiveUnchecked(ciphertext, privateKey, 'ristretto255'),
        ).toThrow(InvalidScalarError);
    });

    it('uses canonical ciphertext encodings for the shipped group id', () => {
        const { publicKey, privateKey } = generateParametersWithPrivateKey(
            12345n,
            'ristretto255',
        );
        const expected = encryptAdditiveWithRandomness(
            7n,
            publicKey,
            4100n,
            20n,
            'ristretto255',
        );

        for (const groupName of ['ristretto255'] as const) {
            const ciphertext = encryptAdditiveWithRandomness(
                7n,
                publicKey,
                4100n,
                20n,
                groupName,
            );

            expect(ciphertext).toEqual(expected);
            expect(
                decryptAdditive(ciphertext, privateKey, groupName, 20n),
            ).toBe(7n);
        }
    });

    it('is deterministic for fixed randomness and changes when randomness changes', () => {
        const { publicKey } = generateParametersWithPrivateKey(
            12345n,
            'ristretto255',
        );
        const first = encryptAdditiveWithRandomness(
            7n,
            publicKey,
            4100n,
            20n,
            'ristretto255',
        );
        const same = encryptAdditiveWithRandomness(
            7n,
            publicKey,
            4100n,
            20n,
            'ristretto255',
        );
        const different = encryptAdditiveWithRandomness(
            7n,
            publicKey,
            4101n,
            20n,
            'ristretto255',
        );

        expect(first).toEqual(same);
        expect(different).not.toEqual(first);
    });

    it('rejects arbitrary group objects at runtime', () => {
        const group = getGroup('ristretto255');
        const { publicKey } = generateParameters('ristretto255');

        expect(() =>
            encryptAdditive(7n, publicKey, group as never, 10n),
        ).toThrow(UnsupportedSuiteError);
    });

    it('rejects invalid deterministic randomness', () => {
        const { publicKey } = generateParameters('ristretto255');

        expect(() =>
            encryptAdditiveWithRandomness(
                7n,
                publicKey,
                0n,
                20n,
                'ristretto255',
            ),
        ).toThrow(InvalidScalarError);
    });

    it('returns null when the BSGS search space is too small', () => {
        const group = getGroup('ristretto255');
        const target = encodePoint(multiplyBase(1n));

        expect(babyStepGiantStep(target, group.g, 0n)).toBeNull();
    });
});
