import { decodePoint, encodePoint, pointAdd } from '../core/ristretto.js';

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

    return {
        c1: encodePoint(pointAdd(decodePoint(left.c1), decodePoint(right.c1))),
        c2: encodePoint(pointAdd(decodePoint(left.c2), decodePoint(right.c2))),
    };
};
