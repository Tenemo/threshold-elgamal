import {
    InvalidScalarError,
    PlaintextDomainError,
    RISTRETTO_GROUP,
    randomScalarInRange,
} from '../core/index.js';
import {
    decodePoint,
    encodePoint,
    multiplyBase,
    pointAdd,
    pointSubtract,
    pointMultiply,
} from '../core/ristretto.js';

import { babyStepGiantStep } from './bsgs.js';
import type { ElgamalCiphertext } from './types.js';
import {
    assertValidAdditiveBound,
    assertValidAdditiveCiphertext,
    assertValidAdditivePlaintext,
    assertValidAdditivePublicKey,
    assertValidPrivateKey,
} from './validation.js';

type ResolvedAdditiveContext = {
    readonly bound: bigint;
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
): ElgamalCiphertext => {
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
    left: ElgamalCiphertext,
    right: ElgamalCiphertext,
): ElgamalCiphertext => {
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
): ElgamalCiphertext => {
    const context = resolveAdditiveContext(bound, 'encryption');

    assertValidAdditivePlaintext(message, context.bound);
    assertValidAdditivePublicKey(publicKey);
    assertEncryptionRandomness(randomness);

    return encryptAdditiveWithValidatedInputs(message, publicKey, randomness);
};

/**
 * Encrypts an additive plaintext with fresh random `r in 1..q-1`.
 */
export const encryptAdditive = (
    message: bigint,
    publicKey: string,
    bound: bigint,
): ElgamalCiphertext => {
    const context = resolveAdditiveContext(bound, 'encryption');
    const randomness = randomScalarInRange(1n, RISTRETTO_GROUP.q);

    return encryptAdditiveWithRandomness(
        message,
        publicKey,
        randomness,
        context.bound,
    );
};

/**
 * Decrypts an additive ciphertext and recovers the bounded plaintext with
 * baby-step giant-step.
 */
export const decryptAdditive = (
    ciphertext: ElgamalCiphertext,
    privateKey: bigint,
    bound: bigint,
): bigint => {
    const context = resolveAdditiveContext(bound, 'decryption');

    assertValidPrivateKey(privateKey);
    assertValidAdditiveCiphertext(ciphertext);

    const c1 = decodePoint(ciphertext.c1, 'Ciphertext c1');
    const c2 = decodePoint(ciphertext.c2, 'Ciphertext c2');
    const sharedSecret = pointMultiply(c1, privateKey);
    const encodedMessage = pointSubtract(c2, sharedSecret);
    const message = babyStepGiantStep(
        encodePoint(encodedMessage),
        RISTRETTO_GROUP.g,
        context.bound,
    );

    if (message === null) {
        throw new PlaintextDomainError(
            'Ciphertext decrypts to a value outside the supplied additive bound',
        );
    }

    return message;
};
