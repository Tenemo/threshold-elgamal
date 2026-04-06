import { combineCiphertextComponents, resolveElgamalGroup } from './helpers.js';
import type { ElgamalCiphertext, ElgamalGroupInput } from './types.js';
import {
    assertValidAdditiveCiphertext,
    assertValidMultiplicativeCiphertext,
} from './validation.js';

export const multiplyEncryptedValues = (
    left: ElgamalCiphertext,
    right: ElgamalCiphertext,
    group: ElgamalGroupInput,
): ElgamalCiphertext => {
    const resolvedGroup = resolveElgamalGroup(group);
    assertValidMultiplicativeCiphertext(left, resolvedGroup);
    assertValidMultiplicativeCiphertext(right, resolvedGroup);

    return combineCiphertextComponents(left, right, resolvedGroup.p);
};

export const addEncryptedValues = (
    left: ElgamalCiphertext,
    right: ElgamalCiphertext,
    group: ElgamalGroupInput,
): ElgamalCiphertext => {
    const resolvedGroup = resolveElgamalGroup(group);
    assertValidAdditiveCiphertext(left, resolvedGroup);
    assertValidAdditiveCiphertext(right, resolvedGroup);

    return combineCiphertextComponents(left, right, resolvedGroup.p);
};
