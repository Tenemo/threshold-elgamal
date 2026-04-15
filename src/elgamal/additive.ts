import {
    RISTRETTO_GROUP,
    assertAdditiveBound,
    assertInSubgroupOrIdentity,
    assertPlaintextAdditive,
    assertValidPublicKey,
    InvalidScalarError,
} from '../core/index';
import {
    decodePoint,
    encodePoint,
    multiplyBase,
    pointAdd,
    pointMultiply,
} from '../core/ristretto';

import type { ElGamalCiphertext } from './types';

type ResolvedAdditiveContext = {
    readonly bound: bigint;
};

/** Validates an additive-mode public key against the built-in suite. */
const assertValidAdditivePublicKey = (publicKey: string): void => {
    assertValidPublicKey(publicKey);
};

/** Validates the caller-supplied additive plaintext bound. */
const assertValidAdditiveBound = (bound: bigint): void =>
    assertAdditiveBound(bound, RISTRETTO_GROUP.q);

/** Validates the plaintext domain and caller-supplied bound for additive mode. */
const assertValidAdditivePlaintext = (value: bigint, bound: bigint): void =>
    assertPlaintextAdditive(value, bound, RISTRETTO_GROUP.q);

/** Validates an additive ciphertext that may already be an aggregate. */
export const assertValidAdditiveCiphertext = (
    ciphertext: ElGamalCiphertext,
): void => {
    assertInSubgroupOrIdentity(ciphertext.c1);
    assertInSubgroupOrIdentity(ciphertext.c2);
};

const resolveAdditiveBound = (
    bound: bigint | undefined,
    operation: 'encryption' | 'decryption',
): bigint => {
    if (typeof bound !== 'bigint') {
        throw new InvalidScalarError(
            `Additive ${operation} requires an explicit plaintext bound`,
        );
    }

    return bound;
};

const resolveAdditiveContext = (
    bound: bigint | undefined,
    operation: 'encryption' | 'decryption',
): ResolvedAdditiveContext => {
    const resolvedBound = resolveAdditiveBound(bound, operation);

    assertValidAdditiveBound(resolvedBound);

    return {
        bound: resolvedBound,
    };
};

const assertEncryptionRandomness = (randomness: bigint): void => {
    if (randomness <= 0n || randomness >= RISTRETTO_GROUP.q) {
        throw new InvalidScalarError(
            'Encryption randomness must be in the range 1..q-1',
        );
    }
};

const encryptAdditiveWithValidatedInputs = (
    message: bigint,
    publicKey: string,
    randomness: bigint,
): ElGamalCiphertext => {
    const publicKeyPoint = decodePoint(publicKey, 'Public key');
    const c1 = multiplyBase(randomness);
    const messageEncoding = multiplyBase(message);
    const sharedSecret = pointMultiply(publicKeyPoint, randomness);
    const c2 = pointAdd(messageEncoding, sharedSecret);

    return {
        c1: encodePoint(c1),
        c2: encodePoint(c2),
    };
};

/**
 * Adds two additive-mode ciphertexts component-wise.
 */
export const addEncryptedValues = (
    left: ElGamalCiphertext,
    right: ElGamalCiphertext,
): ElGamalCiphertext => {
    assertValidAdditiveCiphertext(left);
    assertValidAdditiveCiphertext(right);

    return {
        c1: encodePoint(pointAdd(decodePoint(left.c1), decodePoint(right.c1))),
        c2: encodePoint(pointAdd(decodePoint(left.c2), decodePoint(right.c2))),
    };
};

/**
 * Encrypts an additive plaintext with caller-supplied randomness.
 */
export const encryptAdditiveWithRandomness = (
    message: bigint,
    publicKey: string,
    randomness: bigint,
    bound: bigint,
): ElGamalCiphertext => {
    const context = resolveAdditiveContext(bound, 'encryption');

    assertValidAdditivePlaintext(message, context.bound);
    assertValidAdditivePublicKey(publicKey);
    assertEncryptionRandomness(randomness);

    return encryptAdditiveWithValidatedInputs(message, publicKey, randomness);
};
