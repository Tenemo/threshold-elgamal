/**
 * Additive ElGamal primitives over the built-in Ristretto255 suite.
 *
 * Ballot payload construction, ciphertext aggregation, and threshold decryption
 * all depend on this layer.
 */
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

/**
 * Validates an additive ciphertext that may already represent an aggregate.
 *
 * Both raw ballot ciphertexts and summed ciphertexts share the same structural
 * requirements.
 */
export const assertValidAdditiveCiphertext = (
    ciphertext: ElGamalCiphertext,
): void => {
    assertInSubgroupOrIdentity(ciphertext.c1);
    assertInSubgroupOrIdentity(ciphertext.c2);
};

const requireAdditiveBound = (bound: bigint | undefined): bigint => {
    if (typeof bound !== 'bigint') {
        throw new InvalidScalarError(
            'Additive encryption requires an explicit plaintext bound',
        );
    }

    return bound;
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
 * Adds two additive ciphertexts component-wise.
 *
 * This is the homomorphic step behind ballot aggregation and tally
 * recomputation.
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
 * Encrypts one additive plaintext with caller-supplied randomness.
 *
 * Public ballot builders usually sit one layer above this helper, but advanced
 * consumers and tests can use it directly when they need explicit control over
 * the randomness input and plaintext bound.
 */
export const encryptAdditiveWithRandomness = (
    message: bigint,
    publicKey: string,
    randomness: bigint,
    bound: bigint,
): ElGamalCiphertext => {
    const resolvedBound = requireAdditiveBound(bound);

    assertAdditiveBound(resolvedBound, RISTRETTO_GROUP.q);
    assertPlaintextAdditive(message, resolvedBound, RISTRETTO_GROUP.q);
    assertValidPublicKey(publicKey);
    assertEncryptionRandomness(randomness);

    return encryptAdditiveWithValidatedInputs(message, publicKey, randomness);
};
