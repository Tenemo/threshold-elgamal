import {
    InvalidScalarError,
    PlaintextDomainError,
    randomScalarInRange,
    type CryptoGroup,
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
import { assertEncryptionRandomness, resolveElgamalGroup } from './helpers.js';
import type { ElgamalCiphertext, ElgamalGroupInput } from './types.js';
import {
    assertValidAdditiveBound,
    assertValidAdditiveCiphertext,
    assertValidAdditivePlaintext,
    assertValidAdditivePublicKey,
    assertValidPrivateKey,
} from './validation.js';

type ResolvedAdditiveContext = {
    readonly bound: bigint;
    readonly group: CryptoGroup;
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
    group: ElgamalGroupInput,
    bound: bigint | undefined,
    operation: 'encryption' | 'decryption',
): ResolvedAdditiveContext => {
    const resolvedGroup = resolveElgamalGroup(group);
    const resolvedBound = resolveAdditiveBound(bound, operation);

    assertValidAdditiveBound(resolvedBound, resolvedGroup);

    return {
        bound: resolvedBound,
        group: resolvedGroup,
    };
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
 * Encrypts an additive plaintext with caller-supplied randomness.
 */
export const encryptAdditiveWithRandomness = (
    message: bigint,
    publicKey: string,
    randomness: bigint,
    bound: bigint,
    group: ElgamalGroupInput,
): ElgamalCiphertext => {
    const context = resolveAdditiveContext(group, bound, 'encryption');

    assertValidAdditivePlaintext(message, context.bound, context.group);
    assertValidAdditivePublicKey(publicKey, context.group);
    assertEncryptionRandomness(randomness, context.group.q);

    return encryptAdditiveWithValidatedInputs(message, publicKey, randomness);
};

/**
 * Encrypts an additive plaintext with fresh random `r in 1..q-1`.
 */
export const encryptAdditive = (
    message: bigint,
    publicKey: string,
    group: ElgamalGroupInput,
    bound: bigint,
): ElgamalCiphertext => {
    const context = resolveAdditiveContext(group, bound, 'encryption');
    const randomness = randomScalarInRange(1n, context.group.q);

    return encryptAdditiveWithRandomness(
        message,
        publicKey,
        randomness,
        context.bound,
        group,
    );
};

/**
 * Decrypts an additive ciphertext and recovers the bounded plaintext with
 * baby-step giant-step.
 */
export const decryptAdditive = (
    ciphertext: ElgamalCiphertext,
    privateKey: bigint,
    group: ElgamalGroupInput,
    bound: bigint,
): bigint => {
    const context = resolveAdditiveContext(group, bound, 'decryption');

    assertValidPrivateKey(privateKey, context.group);
    assertValidAdditiveCiphertext(ciphertext, context.group);

    const c1 = decodePoint(ciphertext.c1, 'Ciphertext c1');
    const c2 = decodePoint(ciphertext.c2, 'Ciphertext c2');
    const sharedSecret = pointMultiply(c1, privateKey);
    const encodedMessage = pointSubtract(c2, sharedSecret);
    const message = babyStepGiantStep(
        encodePoint(encodedMessage),
        context.group.g,
        context.bound,
    );

    if (message === null) {
        throw new PlaintextDomainError(
            'Ciphertext decrypts to a value outside the supplied additive bound',
        );
    }

    return message;
};
