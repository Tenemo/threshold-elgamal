import {
    InvalidScalarError,
    modInvP,
    modP,
    modPowP,
    randomScalarInRange,
} from '../core/index.js';

import { assertEncryptionRandomness, resolveElgamalGroup } from './helpers.js';
import type {
    ElgamalCiphertext,
    ElgamalGroupInput,
    ElgamalParameters,
} from './types.js';
import {
    assertValidMultiplicativeCiphertext,
    assertValidMultiplicativePlaintext,
    assertValidMultiplicativePublicKey,
    assertValidPrivateKey,
} from './validation.js';

export const generateParametersWithPrivateKey = (
    privateKey: bigint,
    group: ElgamalGroupInput = 2048,
): ElgamalParameters => {
    const resolvedGroup = resolveElgamalGroup(group);
    assertValidPrivateKey(privateKey, resolvedGroup);
    const publicKey = modPowP(resolvedGroup.g, privateKey, resolvedGroup.p);

    return {
        group: resolvedGroup,
        publicKey,
        privateKey,
    };
};

export const generateParameters = (
    group: ElgamalGroupInput = 2048,
): ElgamalParameters => {
    const resolvedGroup = resolveElgamalGroup(group);
    const privateKey = randomScalarInRange(1n, resolvedGroup.q);
    return generateParametersWithPrivateKey(privateKey, resolvedGroup.name);
};

export const encryptWithRandomness = (
    message: bigint,
    publicKey: bigint,
    randomness: bigint,
    group: ElgamalGroupInput = 2048,
): ElgamalCiphertext => {
    const resolvedGroup = resolveElgamalGroup(group);
    assertValidMultiplicativePlaintext(message, resolvedGroup);
    assertValidMultiplicativePublicKey(publicKey, resolvedGroup);
    assertEncryptionRandomness(randomness, resolvedGroup.q);
    const c1 = modPowP(resolvedGroup.g, randomness, resolvedGroup.p);
    const sharedSecret = modPowP(publicKey, randomness, resolvedGroup.p);
    const c2 = modP(sharedSecret * message, resolvedGroup.p);

    return { c1, c2 };
};

export const encrypt = (
    message: bigint,
    publicKey: bigint,
    group: ElgamalGroupInput = 2048,
): ElgamalCiphertext => {
    const resolvedGroup = resolveElgamalGroup(group);
    const randomness = randomScalarInRange(1n, resolvedGroup.q);

    return encryptWithRandomness(
        message,
        publicKey,
        randomness,
        resolvedGroup.name,
    );
};

export const decrypt = (
    ciphertext: ElgamalCiphertext,
    privateKey: bigint,
    group: ElgamalGroupInput = 2048,
): bigint => {
    const resolvedGroup = resolveElgamalGroup(group);
    assertValidPrivateKey(privateKey, resolvedGroup);
    assertValidMultiplicativeCiphertext(ciphertext, resolvedGroup);

    const sharedSecret = modPowP(ciphertext.c1, privateKey, resolvedGroup.p);

    return modP(
        ciphertext.c2 * modInvP(sharedSecret, resolvedGroup.p),
        resolvedGroup.p,
    );
};

export const maxVotersForExactProduct = (
    maxScore: bigint,
    group: ElgamalGroupInput = 2048,
): bigint => {
    if (maxScore <= 1n) {
        throw new InvalidScalarError(
            'Maximum score must be greater than 1 for exact product bounds',
        );
    }

    const resolvedGroup = resolveElgamalGroup(group);
    let voterCount = 0n;
    let product = 1n;

    while (product * maxScore < resolvedGroup.p) {
        product *= maxScore;
        voterCount += 1n;
    }

    return voterCount;
};
