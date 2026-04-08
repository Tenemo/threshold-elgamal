import {
    assertInSubgroup,
    assertPositiveParticipantIndex,
    assertScalarInZq,
    modPowP,
    type CryptoGroup,
} from '../core/index.js';
import type { Share } from '../threshold/types.js';

import { evaluateCommitmentProduct } from './commitment-product.js';
import type { FeldmanCommitments } from './types.js';

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
    assertPositiveParticipantIndex(share.index);
    assertScalarInZq(share.value, group.q);
    commitments.commitments.forEach((commitment) =>
        assertInSubgroup(commitment, group.p, group.q),
    );

    return (
        modPowP(group.g, share.value, group.p) ===
        evaluateCommitmentProduct(commitments.commitments, share.index, group)
    );
};
