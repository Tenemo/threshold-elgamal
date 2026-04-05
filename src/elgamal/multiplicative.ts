import {
    getGroup,
    InvalidScalarError,
    modInvP,
    modP,
    modPowP,
    randomScalarInRange,
    type CryptoGroup,
} from '../core/index.js';

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

const resolveGroup = (group: ElgamalGroupInput | undefined): CryptoGroup => {
    if (group === undefined) {
        return getGroup();
    }

    if (typeof group === 'object') {
        return group;
    }

    return getGroup(group);
};

export const generateParameters = (
    group: ElgamalGroupInput = getGroup(),
): ElgamalParameters => {
    const resolvedGroup = resolveGroup(group);
    const privateKey = randomScalarInRange(1n, resolvedGroup.q);
    const publicKey = modPowP(resolvedGroup.g, privateKey, resolvedGroup.p);

    return {
        group: resolvedGroup,
        publicKey,
        privateKey,
    };
};

export const encrypt = (
    message: bigint,
    publicKey: bigint,
    group: ElgamalGroupInput = getGroup(),
): ElgamalCiphertext => {
    const resolvedGroup = resolveGroup(group);
    assertValidMultiplicativePlaintext(message, resolvedGroup);
    assertValidMultiplicativePublicKey(publicKey, resolvedGroup);

    const randomness = randomScalarInRange(1n, resolvedGroup.q);
    const c1 = modPowP(resolvedGroup.g, randomness, resolvedGroup.p);
    const sharedSecret = modPowP(publicKey, randomness, resolvedGroup.p);
    const c2 = modP(sharedSecret * message, resolvedGroup.p);

    return { c1, c2 };
};

export const decrypt = (
    ciphertext: ElgamalCiphertext,
    privateKey: bigint,
    group: ElgamalGroupInput = getGroup(),
): bigint => {
    const resolvedGroup = resolveGroup(group);
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
    group: ElgamalGroupInput = getGroup(),
): bigint => {
    if (maxScore <= 1n) {
        throw new InvalidScalarError(
            'Maximum score must be greater than 1 for exact product bounds',
        );
    }

    const resolvedGroup = resolveGroup(group);
    let voterCount = 0n;
    let product = 1n;

    while (product * maxScore < resolvedGroup.p) {
        product *= maxScore;
        voterCount += 1n;
    }

    return voterCount;
};
