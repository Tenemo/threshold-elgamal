import { assertCanonicalRistrettoGroup } from '../core/group-invariants.js';
import {
    assertInSubgroup,
    assertPositiveParticipantIndex,
    assertScalarInZq,
    type CryptoGroup,
} from '../core/index.js';
import { decodePoint, encodePoint, multiplyBase } from '../core/ristretto.js';
import type { Share } from '../threshold/types.js';

import { evaluateCommitmentProduct } from './commitment-product.js';
import type { FeldmanCommitments } from './types.js';

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
            evaluateCommitmentProduct(
                commitments.commitments,
                share.index,
                group,
            ),
        ),
    );
};
