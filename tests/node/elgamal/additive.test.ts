import { describe, expect, it } from 'vitest';

import {
    InvalidScalarError,
    PlaintextDomainError,
    RISTRETTO_GROUP,
} from '#core';
import {
    addEncryptedValues,
    assertValidAdditiveCiphertext,
    babyStepGiantStep,
    encryptAdditiveWithRandomness,
    type ElGamalCiphertext,
} from '#elgamal';
import {
    decodePoint,
    encodePoint,
    multiplyBase,
    pointMultiply,
    pointSubtract,
} from '#src/core/ristretto';

const privateKey = 12345n;
const publicKey = encodePoint(multiplyBase(privateKey));

const additiveIdentity = (): ElGamalCiphertext => {
    const identity = encodePoint(multiplyBase(0n));

    return {
        c1: identity,
        c2: identity,
    } as ElGamalCiphertext;
};

const decryptWithPrivateKey = (
    ciphertext: ElGamalCiphertext,
    bound: bigint,
): bigint => {
    const encodedMessage = encodePoint(
        pointSubtract(
            decodePoint(ciphertext.c2),
            pointMultiply(decodePoint(ciphertext.c1), privateKey),
        ),
    );
    const message = babyStepGiantStep(encodedMessage, RISTRETTO_GROUP.g, bound);

    if (message === null) {
        throw new PlaintextDomainError(
            'Ciphertext decrypts to a value outside the supplied additive bound',
        );
    }

    return message;
};

describe('additive ElGamal', () => {
    it('uses deterministic canonical ciphertext encodings for fixed randomness', () => {
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
        expect(decryptWithPrivateKey(first, 20n)).toBe(7n);
    });

    it('adds ciphertexts homomorphically, including neutral accumulators', () => {
        const left = encryptAdditiveWithRandomness(6n, publicKey, 7n, 20n);
        const right = encryptAdditiveWithRandomness(7n, publicKey, 9n, 20n);
        const sum = addEncryptedValues(left, right);

        expect(decryptWithPrivateKey(sum, 20n)).toBe(13n);

        const neutralAggregate = addEncryptedValues(additiveIdentity(), left);
        expect(neutralAggregate).toEqual(left);
        expect(() =>
            assertValidAdditiveCiphertext(neutralAggregate),
        ).not.toThrow();
    });

    it('accepts aggregate ciphertexts with identity c1', () => {
        const left = encryptAdditiveWithRandomness(6n, publicKey, 7n, 20n);
        const right = encryptAdditiveWithRandomness(
            7n,
            publicKey,
            RISTRETTO_GROUP.q - 7n,
            20n,
        );
        const sum = addEncryptedValues(left, right);
        const identity = encodePoint(multiplyBase(0n));

        expect(sum.c1).toBe(identity);
        expect(() => assertValidAdditiveCiphertext(sum)).not.toThrow();
        expect(decryptWithPrivateKey(sum, 20n)).toBe(13n);
    });

    it('rejects invalid additive plaintexts, bounds, and randomness', () => {
        expect(() =>
            encryptAdditiveWithRandomness(-1n, publicKey, 7n, 10n),
        ).toThrow(PlaintextDomainError);
        expect(() =>
            encryptAdditiveWithRandomness(11n, publicKey, 7n, 10n),
        ).toThrow(PlaintextDomainError);
        expect(() =>
            encryptAdditiveWithRandomness(7n, publicKey, 0n, 20n),
        ).toThrow(InvalidScalarError);
        expect(() =>
            encryptAdditiveWithRandomness(7n, publicKey, 7n, RISTRETTO_GROUP.q),
        ).toThrow(InvalidScalarError);
        const encryptUnchecked = encryptAdditiveWithRandomness as (
            ...args: unknown[]
        ) => unknown;
        expect(() => encryptUnchecked(7n, publicKey, 7n)).toThrow(
            InvalidScalarError,
        );
    });

    it('fails to decode when the BSGS search space is too small', () => {
        const ciphertext = encryptAdditiveWithRandomness(
            1n,
            publicKey,
            7n,
            10n,
        );

        expect(() => decryptWithPrivateKey(ciphertext, 0n)).toThrow(
            PlaintextDomainError,
        );
    });
});
