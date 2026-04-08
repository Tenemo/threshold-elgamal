import {
    assertInSubgroup,
    assertScalarInZq,
    assertValidParticipantIndex,
    modP,
    modPowP,
    type CryptoGroup,
} from '../core/index.js';
import type { Share } from '../threshold/types.js';

import type { FeldmanCommitments } from './types.js';

const evaluateCommitmentProduct = (
    commitments: readonly bigint[],
    index: number,
    group: CryptoGroup,
): bigint => {
    let result = 1n;
    let exponent = 1n;
    const point = BigInt(index);

    for (const commitment of commitments) {
        result = modP(result * modPowP(commitment, exponent, group.p), group.p);
        exponent = (exponent * point) % group.q;
    }

    return result;
};

/**
 * Computes Feldman commitments for polynomial coefficients.
 *
 * @param polynomial Polynomial coefficients in ascending order.
 * @param group Resolved group definition.
 * @returns Feldman commitments for every coefficient.
 */
export const generateFeldmanCommitments = (
    polynomial: readonly bigint[],
    group: CryptoGroup,
): FeldmanCommitments => ({
    commitments: polynomial.map((coefficient) => {
        assertScalarInZq(coefficient, group.q);
        return modPowP(group.g, coefficient, group.p);
    }),
});

/**
 * Verifies a Feldman share against the published coefficient commitments.
 *
 * @param share Indexed secret share.
 * @param commitments Published Feldman commitments.
 * @param group Resolved group definition.
 * @returns `true` when the share matches the commitments.
 */
export const verifyFeldmanShare = (
    share: Share,
    commitments: FeldmanCommitments,
    group: CryptoGroup,
): boolean => {
    assertValidParticipantIndex(share.index, Number.MAX_SAFE_INTEGER);
    assertScalarInZq(share.value, group.q);
    commitments.commitments.forEach((commitment) =>
        assertInSubgroup(commitment, group.p, group.q),
    );

    return (
        modPowP(group.g, share.value, group.p) ===
        evaluateCommitmentProduct(commitments.commitments, share.index, group)
    );
};
