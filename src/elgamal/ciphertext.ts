import { combineCiphertextComponents, resolveElgamalGroup } from './helpers.js';
import type { ElgamalCiphertext, ElgamalGroupInput } from './types.js';
import { assertValidAdditiveCiphertext } from './validation.js';

/**
 * Adds two additive-mode ciphertexts component-wise.
 *
 * Use the same group and operational plaintext bound across all ciphertexts in
 * a tally.
 *
 * @example
 * ```ts
 * const sum = addEncryptedValues(left, right, 'ffdhe3072');
 * ```
 *
 * @throws `InvalidCiphertextError` When either ciphertext is not valid for
 * additive mode.
 */
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
