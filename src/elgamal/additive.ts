import {
    InvalidScalarError,
    PlaintextDomainError,
    modInvP,
    modP,
    modPowP,
    randomScalarInRange,
} from '../core/index.js';

import { babyStepGiantStep } from './bsgs.js';
import { assertEncryptionRandomness, resolveElgamalGroup } from './helpers.js';
import type { ElgamalCiphertext, ElgamalGroupInput } from './types.js';
import {
    assertValidAdditiveCiphertext,
    assertValidAdditivePlaintext,
    assertValidAdditivePublicKey,
    assertValidPrivateKey,
} from './validation.js';

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

/**
 * Encrypts an additive plaintext with caller-supplied randomness.
 *
 * The plaintext is encoded as `g^m`, so decryption succeeds only when the same
 * bound is later supplied to the bounded discrete-log solver.
 *
 * @throws {@link InvalidScalarError} When `randomness` or `bound` is invalid.
 * @throws {@link PlaintextDomainError} When `message` falls outside `0..bound`.
 *
 * @example
 * ```ts
 * const ciphertext = encryptAdditiveWithRandomness(7n, publicKey, 42n, 20n, 'ffdhe3072');
 * ```
 */
export const encryptAdditiveWithRandomness = (
    message: bigint,
    publicKey: bigint,
    randomness: bigint,
    bound: bigint,
    group: ElgamalGroupInput,
): ElgamalCiphertext => {
    const resolvedGroup = resolveElgamalGroup(group);
    const resolvedBound = resolveAdditiveBound(bound, 'encryption');
    assertValidAdditivePlaintext(message, resolvedBound, resolvedGroup);
    assertValidAdditivePublicKey(publicKey, resolvedGroup);
    assertEncryptionRandomness(randomness, resolvedGroup.q);
    const c1 = modPowP(resolvedGroup.g, randomness, resolvedGroup.p);
    const messageEncoding = modPowP(resolvedGroup.g, message, resolvedGroup.p);
    const sharedSecret = modPowP(publicKey, randomness, resolvedGroup.p);
    const c2 = modP(messageEncoding * sharedSecret, resolvedGroup.p);

    return { c1, c2 };
};

export function encryptAdditive(
    message: bigint,
    publicKey: bigint,
    group: ElgamalGroupInput,
    bound: bigint,
): ElgamalCiphertext;
/**
 * Encrypts an additive plaintext with fresh random `r in 1..q-1`.
 *
 * Use this mode for confidential sums where plaintexts stay within a known
 * bounded range.
 *
 * @throws {@link InvalidScalarError} When `bound` is missing or invalid.
 * @throws {@link PlaintextDomainError} When `message` falls outside `0..bound`.
 *
 * @example
 * ```ts
 * const ciphertext = encryptAdditive(6n, publicKey, 'ffdhe3072', 20n);
 * ```
 */
export function encryptAdditive(
    message: bigint,
    publicKey: bigint,
    group: ElgamalGroupInput,
    bound: bigint,
): ElgamalCiphertext {
    const resolvedGroup = resolveElgamalGroup(group);
    const resolvedBound = resolveAdditiveBound(bound, 'encryption');
    const randomness = randomScalarInRange(1n, resolvedGroup.q);

    return encryptAdditiveWithRandomness(
        message,
        publicKey,
        randomness,
        resolvedBound,
        group,
    );
}

export function decryptAdditive(
    ciphertext: ElgamalCiphertext,
    privateKey: bigint,
    group: ElgamalGroupInput,
    bound: bigint,
): bigint;
/**
 * Decrypts an additive ciphertext and recovers the bounded plaintext with
 * baby-step giant-step.
 *
 * The supplied `bound` must match the operational range used for the ciphertext
 * or decryption may fail even when the key is correct.
 *
 * @throws {@link InvalidScalarError} When `bound` is missing or invalid.
 * @throws {@link PlaintextDomainError} When the decrypted plaintext lies
 * outside the supplied bound.
 *
 * @example
 * ```ts
 * const message = decryptAdditive(ciphertext, privateKey, 'ffdhe3072', 20n);
 * ```
 */
export function decryptAdditive(
    ciphertext: ElgamalCiphertext,
    privateKey: bigint,
    group: ElgamalGroupInput,
    bound: bigint,
): bigint {
    const resolvedGroup = resolveElgamalGroup(group);
    const resolvedBound = resolveAdditiveBound(bound, 'decryption');
    assertValidPrivateKey(privateKey, resolvedGroup);
    assertValidAdditiveCiphertext(ciphertext, resolvedGroup);
    assertValidAdditivePlaintext(0n, resolvedBound, resolvedGroup);

    const sharedSecret = modPowP(ciphertext.c1, privateKey, resolvedGroup.p);
    const encodedMessage = modP(
        ciphertext.c2 * modInvP(sharedSecret, resolvedGroup.p),
        resolvedGroup.p,
    );
    const message = babyStepGiantStep(
        encodedMessage,
        resolvedGroup.g,
        resolvedGroup.p,
        resolvedBound,
    );

    if (message === null) {
        throw new PlaintextDomainError(
            'Ciphertext decrypts to a value outside the supplied additive bound',
        );
    }

    return message;
}
