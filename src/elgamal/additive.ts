import {
    getGroup,
    PlaintextDomainError,
    modInvP,
    modP,
    modPowP,
    randomScalarInRange,
    type CryptoGroup,
} from '../core/index.js';

import { babyStepGiantStep } from './bsgs.js';
import type { ElgamalCiphertext, ElgamalGroupInput } from './types.js';
import {
    assertValidAdditiveCiphertext,
    assertValidAdditivePlaintext,
    assertValidAdditivePublicKey,
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

export const encryptAdditive = (
    message: bigint,
    publicKey: bigint,
    group: ElgamalGroupInput = getGroup(),
    bound?: bigint,
): ElgamalCiphertext => {
    const resolvedGroup = resolveGroup(group);
    const resolvedBound = bound ?? resolvedGroup.q - 1n;
    assertValidAdditivePlaintext(message, resolvedBound, resolvedGroup);
    assertValidAdditivePublicKey(publicKey, resolvedGroup);

    const randomness = randomScalarInRange(1n, resolvedGroup.q);
    const c1 = modPowP(resolvedGroup.g, randomness, resolvedGroup.p);
    const messageEncoding = modPowP(resolvedGroup.g, message, resolvedGroup.p);
    const sharedSecret = modPowP(publicKey, randomness, resolvedGroup.p);
    const c2 = modP(messageEncoding * sharedSecret, resolvedGroup.p);

    return { c1, c2 };
};

export const decryptAdditive = (
    ciphertext: ElgamalCiphertext,
    privateKey: bigint,
    group: ElgamalGroupInput = getGroup(),
    bound: bigint,
): bigint => {
    const resolvedGroup = resolveGroup(group);
    assertValidPrivateKey(privateKey, resolvedGroup);
    assertValidAdditiveCiphertext(ciphertext, resolvedGroup);
    assertValidAdditivePlaintext(0n, bound, resolvedGroup);

    const sharedSecret = modPowP(ciphertext.c1, privateKey, resolvedGroup.p);
    const encodedMessage = modP(
        ciphertext.c2 * modInvP(sharedSecret, resolvedGroup.p),
        resolvedGroup.p,
    );
    const message = babyStepGiantStep(
        encodedMessage,
        resolvedGroup.g,
        resolvedGroup.p,
        bound,
    );

    if (message === null) {
        throw new PlaintextDomainError(
            'Ciphertext decrypts to a value outside the supplied additive bound',
        );
    }

    return message;
};
