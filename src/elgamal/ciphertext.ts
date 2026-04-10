import { combineCiphertextComponents, resolveElgamalGroup } from './helpers.js';
import type { ElgamalCiphertext, ElgamalGroupInput } from './types.js';
import { assertValidAdditiveCiphertext } from './validation.js';

/**
 * Adds two additive-mode ciphertexts component-wise.
 */
export const addEncryptedValues = (
    left: ElgamalCiphertext,
    right: ElgamalCiphertext,
    group: ElgamalGroupInput,
): ElgamalCiphertext => {
    const resolvedGroup = resolveElgamalGroup(group);
    assertValidAdditiveCiphertext(left, resolvedGroup);
    assertValidAdditiveCiphertext(right, resolvedGroup);

    return combineCiphertextComponents(left, right);
};
