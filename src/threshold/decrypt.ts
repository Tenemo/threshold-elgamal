import {
    assertInSubgroupOrIdentity,
    assertScalarInZq,
    IndexOutOfRangeError,
    InvalidShareError,
    PlaintextDomainError,
    modQ,
    type CryptoGroup,
} from '../core/index.js';
import {
    decodePoint,
    encodePoint,
    pointAdd,
    pointMultiply,
    pointSubtract,
    RISTRETTO_ZERO,
} from '../core/ristretto.js';
import { babyStepGiantStep } from '../elgamal/bsgs.js';
import type { ElgamalCiphertext } from '../elgamal/types.js';

import { lagrangeCoefficient } from './lagrange.js';
import type {
    DecryptionShare,
    Share,
    VerifiedAggregateCiphertext,
} from './types.js';

const assertPositiveIndex = (index: number, label: string): void => {
    if (!Number.isInteger(index) || index < 1) {
        throw new IndexOutOfRangeError(
            `${label} index must be a positive integer`,
        );
    }
};

const assertUniqueIndices = (
    indices: readonly number[],
    label: string,
): void => {
    const seen = new Set<number>();

    for (const index of indices) {
        if (seen.has(index)) {
            throw new InvalidShareError(`${label} indices must be unique`);
        }
        seen.add(index);
    }
};

/**
 * Creates a partial decryption share `d_i = x_i C_1`.
 */
export const createDecryptionShare = (
    ciphertext: ElgamalCiphertext,
    share: Share,
    group: CryptoGroup,
): DecryptionShare => {
    assertPositiveIndex(share.index, 'Share');
    assertScalarInZq(share.value, group.q);
    assertInSubgroupOrIdentity(ciphertext.c1);

    return {
        index: share.index,
        value: encodePoint(
            pointMultiply(decodePoint(ciphertext.c1), share.value),
        ),
    };
};

/**
 * Combines indexed decryption shares via Lagrange interpolation at `x = 0`.
 */
export const combineDecryptionShares = (
    ciphertext: ElgamalCiphertext,
    decryptionShares: readonly DecryptionShare[],
    group: CryptoGroup,
    bound: bigint,
): bigint => {
    if (decryptionShares.length === 0) {
        throw new InvalidShareError(
            'At least one decryption share is required for reconstruction',
        );
    }

    assertInSubgroupOrIdentity(ciphertext.c1);
    assertInSubgroupOrIdentity(ciphertext.c2);

    const indices = decryptionShares.map((share) => {
        assertPositiveIndex(share.index, 'Decryption share');
        assertInSubgroupOrIdentity(share.value);
        return share.index;
    });

    assertUniqueIndices(indices, 'Decryption share');

    const bigintIndices = indices.map((index) => BigInt(index));
    let combinedFactor = RISTRETTO_ZERO;

    for (const share of decryptionShares) {
        const lambda = lagrangeCoefficient(
            BigInt(share.index),
            bigintIndices,
            group.q,
        );
        combinedFactor = pointAdd(
            combinedFactor,
            pointMultiply(decodePoint(share.value), modQ(lambda, group.q)),
        );
    }

    const encodedMessage = pointSubtract(
        decodePoint(ciphertext.c2),
        combinedFactor,
    );
    const message = babyStepGiantStep(
        encodePoint(encodedMessage),
        group.g,
        bound,
    );

    if (message === null) {
        throw new PlaintextDomainError(
            'Threshold decryption result exceeds the supplied additive bound',
        );
    }

    return message;
};

/**
 * Creates a decryption share only for a locally recomputed aggregate that is
 * anchored to a canonical transcript hash.
 */
export const createVerifiedDecryptionShare = (
    aggregate: VerifiedAggregateCiphertext,
    share: Share,
    group: CryptoGroup,
): DecryptionShare => {
    if (aggregate.transcriptHash.trim() === '') {
        throw new InvalidShareError(
            'Verified aggregate ciphertext requires a non-empty transcript hash',
        );
    }
    if (!Number.isInteger(aggregate.ballotCount) || aggregate.ballotCount < 1) {
        throw new InvalidShareError(
            'Verified aggregate ciphertext requires at least one accepted ballot',
        );
    }

    return createDecryptionShare(aggregate.ciphertext, share, group);
};
