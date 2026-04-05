import { modP } from '../core/index.js';

import { resolveElgamalGroup } from './group.js';
import type { ElgamalCiphertext, ElgamalGroupInput } from './types.js';
import {
    assertValidAdditiveCiphertext,
    assertValidMultiplicativeCiphertext,
} from './validation.js';

export const multiplyEncryptedValues = (
    left: ElgamalCiphertext,
    right: ElgamalCiphertext,
    group: ElgamalGroupInput = 2048,
): ElgamalCiphertext => {
    const resolvedGroup = resolveElgamalGroup(group);
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
    group: ElgamalGroupInput = 2048,
): ElgamalCiphertext => {
    const resolvedGroup = resolveElgamalGroup(group);
    assertValidAdditiveCiphertext(left, resolvedGroup);
    assertValidAdditiveCiphertext(right, resolvedGroup);

    return {
        c1: modP(left.c1 * right.c1, resolvedGroup.p),
        c2: modP(left.c2 * right.c2, resolvedGroup.p),
    };
};
