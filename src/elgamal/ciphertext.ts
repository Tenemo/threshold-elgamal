import { getGroup, modP, type CryptoGroup } from '../core/index.js';

import type { ElgamalCiphertext, ElgamalGroupInput } from './types.js';
import {
    assertValidAdditiveCiphertext,
    assertValidMultiplicativeCiphertext,
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

export const multiplyEncryptedValues = (
    left: ElgamalCiphertext,
    right: ElgamalCiphertext,
    group: ElgamalGroupInput = getGroup(),
): ElgamalCiphertext => {
    const resolvedGroup = resolveGroup(group);
    assertValidMultiplicativeCiphertext(left, resolvedGroup);
    assertValidMultiplicativeCiphertext(right, resolvedGroup);

    return {
        c1: modP(left.c1 * right.c1, resolvedGroup.p),
        c2: modP(left.c2 * right.c2, resolvedGroup.p),
    };
};

export const addEncryptedValues = (
    left: ElgamalCiphertext,
    right: ElgamalCiphertext,
    group: ElgamalGroupInput = getGroup(),
): ElgamalCiphertext => {
    const resolvedGroup = resolveGroup(group);
    assertValidAdditiveCiphertext(left, resolvedGroup);
    assertValidAdditiveCiphertext(right, resolvedGroup);

    return {
        c1: modP(left.c1 * right.c1, resolvedGroup.p),
        c2: modP(left.c2 * right.c2, resolvedGroup.p),
    };
};
