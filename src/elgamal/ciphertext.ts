import { combineCiphertextComponents } from './helpers.js';
import type { ElgamalCiphertext } from './types.js';
import { assertValidAdditiveCiphertext } from './validation.js';

/**
 * Adds two additive-mode ciphertexts component-wise.
 */
export const addEncryptedValues = (
    left: ElgamalCiphertext,
    right: ElgamalCiphertext,
): ElgamalCiphertext => {
    assertValidAdditiveCiphertext(left);
    assertValidAdditiveCiphertext(right);

    return combineCiphertextComponents(left, right);
};
