import {
    InvalidScalarError,
    PlaintextDomainError,
    type CryptoGroup,
    modInvP,
    modP,
    modPowP,
    randomScalarInRange,
} from '../core/index.js';

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
    publicKey: bigint,
    randomness: bigint,
    group: CryptoGroup,
): ElgamalCiphertext => {
    const c1 = modPowP(group.g, randomness, group.p);
    const messageEncoding = modPowP(group.g, message, group.p);
    const sharedSecret = modPowP(publicKey, randomness, group.p);
    const c2 = modP(messageEncoding * sharedSecret, group.p);

    return { c1, c2 };
};

/**
 * Encrypts an additive plaintext with caller-supplied randomness.
 *
 * The plaintext is encoded as `g^m`. The `bound` passed here validates the
 * single plaintext being encrypted and is not stored in the ciphertext.
 *
 * @param message Plaintext in the range `0..bound`.
 * @param publicKey Additive-mode public key for the selected group.
 * @param randomness Encryption randomness in the range `1..q-1`.
 * @param bound Maximum plaintext accepted for this encryption call.
 * @param group Built-in group identifier shared by the key and ciphertext.
 * @returns A fresh additive ciphertext `(c1, c2)`.
 *
 * @throws {@link InvalidScalarError} When `randomness` or `bound` is invalid.
 * @throws {@link InvalidGroupElementError} When `publicKey` is not a valid
 * subgroup public key for `group`.
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
    const context = resolveAdditiveContext(group, bound, 'encryption');

    assertValidAdditivePlaintext(message, context.bound, context.group);
    assertValidAdditivePublicKey(publicKey, context.group);
    assertEncryptionRandomness(randomness, context.group.q);

    return encryptAdditiveWithValidatedInputs(
        message,
        publicKey,
        randomness,
        context.group,
    );
};
/**
 * Encrypts an additive plaintext with fresh random `r in 1..q-1`.
 *
 * Use this mode for confidential sums where plaintexts stay within a known
 * bounded range.
 *
 * @param message Plaintext in the range `0..bound`.
 * @param publicKey Additive-mode public key for the selected group.
 * @param group Built-in group identifier shared by the key and ciphertext.
 * @param bound Maximum plaintext accepted for this encryption call.
 * @returns A fresh additive ciphertext `(c1, c2)`.
 *
 * @throws {@link InvalidScalarError} When `bound` is missing or invalid.
 * @throws {@link InvalidGroupElementError} When `publicKey` is not a valid
 * subgroup public key for `group`.
 * @throws {@link PlaintextDomainError} When `message` falls outside `0..bound`.
 *
 * @example
 * ```ts
 * const ciphertext = encryptAdditive(6n, publicKey, 'ffdhe3072', 20n);
 * ```
 */
export const encryptAdditive = (
    message: bigint,
    publicKey: bigint,
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
 *
 * The supplied `bound` must cover the plaintext you expect to recover. For
 * aggregate decryption this is usually the maximum tally, which can be larger
 * than the bounds used to validate individual plaintexts during encryption. The
 * library does not store or authenticate this bound inside the ciphertext.
 *
 * @param ciphertext Additive ciphertext to decrypt.
 * @param privateKey Private key in the range `1..q-1`.
 * @param group Built-in group identifier shared by the key and ciphertext.
 * @param bound Maximum plaintext to search for during bounded recovery.
 * @returns The recovered plaintext as a bigint.
 *
 * @throws {@link InvalidScalarError} When `bound` is missing or invalid.
 * @throws {@link InvalidGroupElementError} When `ciphertext` is not valid for
 * the selected group.
 * @throws {@link PlaintextDomainError} When the decrypted plaintext lies
 * outside the supplied bound.
 *
 * @example
 * ```ts
 * const message = decryptAdditive(ciphertext, privateKey, 'ffdhe3072', 20n);
 * ```
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

    const sharedSecret = modPowP(ciphertext.c1, privateKey, context.group.p);
    const encodedMessage = modP(
        ciphertext.c2 * modInvP(sharedSecret, context.group.p),
        context.group.p,
    );
    const message = babyStepGiantStep(
        encodedMessage,
        context.group.g,
        context.group.p,
        context.bound,
    );

    if (message === null) {
        throw new PlaintextDomainError(
            'Ciphertext decrypts to a value outside the supplied additive bound',
        );
    }

    return message;
};
