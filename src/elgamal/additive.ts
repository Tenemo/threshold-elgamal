import {
    InvalidScalarError,
    PlaintextDomainError,
    modInvP,
    modP,
    modPowP,
    randomScalarInRange,
} from '../core/index.js';

import { babyStepGiantStep } from './bsgs.js';
import { resolveElgamalGroup } from './group.js';
import type { ElgamalCiphertext, ElgamalGroupInput } from './types.js';
import {
    assertValidAdditiveCiphertext,
    assertValidAdditivePlaintext,
    assertValidAdditivePublicKey,
    assertValidPrivateKey,
} from './validation.js';

const assertEncryptionRandomness = (randomness: bigint, q: bigint): void => {
    if (randomness <= 0n || randomness >= q) {
        throw new InvalidScalarError(
            'Encryption randomness must be in the range 1..q-1',
        );
    }
};

const resolveAdditiveBound = (
    groupOrBound: ElgamalGroupInput | bigint,
    bound: bigint | undefined,
    operation: 'encryption' | 'decryption',
): { bound: bigint; group: ElgamalGroupInput } => {
    if (typeof groupOrBound === 'bigint') {
        return { bound: groupOrBound, group: 2048 };
    }

    if (bound === undefined) {
        throw new InvalidScalarError(
            `Additive ${operation} requires an explicit plaintext bound`,
        );
    }

    return { bound, group: groupOrBound };
};

export const encryptAdditiveWithRandomness = (
    message: bigint,
    publicKey: bigint,
    randomness: bigint,
    bound: bigint,
    group: ElgamalGroupInput = 2048,
): ElgamalCiphertext => {
    const resolvedGroup = resolveElgamalGroup(group);
    assertValidAdditivePlaintext(message, bound, resolvedGroup);
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
    bound: bigint,
): ElgamalCiphertext;
export function encryptAdditive(
    message: bigint,
    publicKey: bigint,
    group: ElgamalGroupInput,
    bound: bigint,
): ElgamalCiphertext;
export function encryptAdditive(
    message: bigint,
    publicKey: bigint,
    groupOrBound: ElgamalGroupInput | bigint,
    bound?: bigint,
): ElgamalCiphertext {
    const resolvedInput = resolveAdditiveBound(
        groupOrBound,
        bound,
        'encryption',
    );
    const resolvedGroup = resolveElgamalGroup(resolvedInput.group);
    const randomness = randomScalarInRange(1n, resolvedGroup.q);

    return encryptAdditiveWithRandomness(
        message,
        publicKey,
        randomness,
        resolvedInput.bound,
        resolvedGroup.name,
    );
}

export function decryptAdditive(
    ciphertext: ElgamalCiphertext,
    privateKey: bigint,
    bound: bigint,
): bigint;
export function decryptAdditive(
    ciphertext: ElgamalCiphertext,
    privateKey: bigint,
    group: ElgamalGroupInput,
    bound: bigint,
): bigint;
export function decryptAdditive(
    ciphertext: ElgamalCiphertext,
    privateKey: bigint,
    groupOrBound: ElgamalGroupInput | bigint,
    bound?: bigint,
): bigint {
    const resolvedInput = resolveAdditiveBound(
        groupOrBound,
        bound,
        'decryption',
    );
    const resolvedGroup = resolveElgamalGroup(resolvedInput.group);
    assertValidPrivateKey(privateKey, resolvedGroup);
    assertValidAdditiveCiphertext(ciphertext, resolvedGroup);
    assertValidAdditivePlaintext(0n, resolvedInput.bound, resolvedGroup);

    const sharedSecret = modPowP(ciphertext.c1, privateKey, resolvedGroup.p);
    const encodedMessage = modP(
        ciphertext.c2 * modInvP(sharedSecret, resolvedGroup.p),
        resolvedGroup.p,
    );
    const message = babyStepGiantStep(
        encodedMessage,
        resolvedGroup.g,
        resolvedGroup.p,
        resolvedInput.bound,
    );

    if (message === null) {
        throw new PlaintextDomainError(
            'Ciphertext decrypts to a value outside the supplied additive bound',
        );
    }

    return message;
}
