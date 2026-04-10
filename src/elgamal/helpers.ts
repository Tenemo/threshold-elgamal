import { InvalidScalarError, RISTRETTO_GROUP } from '../core/index.js';
import {
    decodePoint,
    encodePoint,
    pointAdd,
    type InternalPoint,
} from '../core/ristretto.js';

import type { ElgamalCiphertext } from './types.js';

export const assertEncryptionRandomness = (randomness: bigint): void => {
    if (randomness <= 0n || randomness >= RISTRETTO_GROUP.q) {
        throw new InvalidScalarError(
            'Encryption randomness must be in the range 1..q-1',
        );
    }
};

export const combineCiphertextComponents = (
    left: ElgamalCiphertext,
    right: ElgamalCiphertext,
): ElgamalCiphertext => ({
    c1: encodePoint(pointAdd(decodePoint(left.c1), decodePoint(right.c1))),
    c2: encodePoint(pointAdd(decodePoint(left.c2), decodePoint(right.c2))),
});

export const pointFromCiphertext = (
    ciphertext: ElgamalCiphertext,
): { readonly c1: InternalPoint; readonly c2: InternalPoint } => ({
    c1: decodePoint(ciphertext.c1),
    c2: decodePoint(ciphertext.c2),
});
