import {
    assertInSubgroup,
    assertPositiveParticipantIndex,
    assertScalarInZq,
    modQ,
    RISTRETTO_GROUP,
    assertCanonicalRistrettoGroup,
    type CryptoGroup,
} from '../core/index';
import {
    decodePoint,
    encodePoint,
    multiplyBase,
    pointAdd,
    pointMultiply,
    RISTRETTO_ZERO,
} from '../core/ristretto';
import type { EncodedPoint } from '../core/types';
import type { Share } from '../threshold/types';

import type { FeldmanCommitments } from './types';

export const evaluateCommitmentProduct = (
    commitments: readonly EncodedPoint[],
    index: number,
): EncodedPoint => {
    let result = RISTRETTO_ZERO;
    let exponent = 1n;
    const point = BigInt(index);

    for (const commitment of commitments) {
        result = pointAdd(
            result,
            pointMultiply(decodePoint(commitment), exponent),
        );
        exponent = modQ(exponent * point, RISTRETTO_GROUP.q);
    }

    return encodePoint(result);
};

/**
 * Computes Feldman commitments for polynomial coefficients.
 */
export const generateFeldmanCommitments = (
    polynomial: readonly bigint[],
    group: CryptoGroup,
): FeldmanCommitments => {
    assertCanonicalRistrettoGroup(group, 'Feldman commitment group');

    return {
        commitments: polynomial.map((coefficient) => {
            assertScalarInZq(coefficient, group.q);
            return encodePoint(multiplyBase(coefficient));
        }),
    };
};

/**
 * Verifies a Feldman share against the published coefficient commitments.
 */
export const verifyFeldmanShare = (
    share: Share,
    commitments: FeldmanCommitments,
    group: CryptoGroup,
): boolean => {
    assertCanonicalRistrettoGroup(group, 'Feldman verification group');
    assertPositiveParticipantIndex(share.index);
    assertScalarInZq(share.value, group.q);
    commitments.commitments.forEach((commitment) =>
        assertInSubgroup(commitment),
    );

    return decodePoint(encodePoint(multiplyBase(share.value))).equals(
        decodePoint(
            evaluateCommitmentProduct(commitments.commitments, share.index),
        ),
    );
};
