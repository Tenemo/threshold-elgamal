import {
    assertInSubgroupOrIdentity,
    assertScalarInZq,
    IndexOutOfRangeError,
    InvalidShareError,
    PlaintextDomainError,
    RISTRETTO_GROUP,
    modInvQ,
    modQ,
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

import type { DecryptionShare, Share } from './types.js';

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
 * Computes the Lagrange coefficient for `participantIndex` at `x = 0`.
 *
 * @param participantIndex Target share index as a bigint.
 * @param allIndices Full subset of indices participating in reconstruction.
 * @param q Prime-order subgroup order.
 * @returns `lambda_i mod q`.
 */
export const lagrangeCoefficient = (
    participantIndex: bigint,
    allIndices: readonly bigint[],
    q: bigint,
): bigint => {
    let numerator = 1n;
    let denominator = 1n;

    for (const otherIndex of allIndices) {
        if (otherIndex === participantIndex) {
            continue;
        }

        numerator = modQ(numerator * otherIndex, q);
        denominator = modQ(
            denominator * modQ(otherIndex - participantIndex, q),
            q,
        );
    }

    return modQ(numerator * modInvQ(denominator, q), q);
};

/**
 * Creates a partial decryption share `d_i = x_i C_1`.
 */
export const createDecryptionShare = (
    ciphertext: ElgamalCiphertext,
    share: Share,
): DecryptionShare => {
    assertPositiveIndex(share.index, 'Share');
    assertScalarInZq(share.value, RISTRETTO_GROUP.q);
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
            RISTRETTO_GROUP.q,
        );
        combinedFactor = pointAdd(
            combinedFactor,
            pointMultiply(
                decodePoint(share.value),
                modQ(lambda, RISTRETTO_GROUP.q),
            ),
        );
    }

    const encodedMessage = pointSubtract(
        decodePoint(ciphertext.c2),
        combinedFactor,
    );
    const message = babyStepGiantStep(
        encodePoint(encodedMessage),
        RISTRETTO_GROUP.g,
        bound,
    );

    if (message === null) {
        throw new PlaintextDomainError(
            'Threshold decryption result exceeds the supplied additive bound',
        );
    }

    return message;
};
