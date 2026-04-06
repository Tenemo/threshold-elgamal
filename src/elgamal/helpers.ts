import {
    getGroup,
    InvalidScalarError,
    modP,
    type CryptoGroup,
} from '../core/index.js';

import type { ElgamalCiphertext, ElgamalGroupInput } from './types.js';

export const resolveElgamalGroup = (
    group: ElgamalGroupInput | undefined,
): CryptoGroup => getGroup(group ?? 2048);

export const assertEncryptionRandomness = (
    randomness: bigint,
    q: bigint,
): void => {
    if (randomness <= 0n || randomness >= q) {
        throw new InvalidScalarError(
            'Encryption randomness must be in the range 1..q-1',
        );
    }
};

export const combineCiphertextComponents = (
    left: ElgamalCiphertext,
    right: ElgamalCiphertext,
    p: bigint,
): ElgamalCiphertext => ({
    c1: modP(left.c1 * right.c1, p),
    c2: modP(left.c2 * right.c2, p),
});
