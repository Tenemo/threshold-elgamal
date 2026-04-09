import {
    assertInSubgroup,
    assertPositiveParticipantIndex,
    assertScalarInZq,
    ThresholdViolationError,
    multiExponentiate,
    type CryptoGroup,
} from '../core/index.js';
import {
    evaluatePolynomial,
    type Polynomial,
} from '../threshold/polynomial.js';

import { evaluateCommitmentProduct } from './commitment-product.js';
import type { PedersenCommitments, PedersenShare } from './types.js';

/**
 * Computes Pedersen commitments for matching secret and blinding polynomials.
 *
 * @param secretPolynomial Secret polynomial coefficients.
 * @param blindingPolynomial Blinding polynomial coefficients.
 * @param group Resolved group definition.
 * @returns Pedersen commitments for every coefficient pair.
 */
export const generatePedersenCommitments = (
    secretPolynomial: readonly bigint[],
    blindingPolynomial: readonly bigint[],
    group: CryptoGroup,
): PedersenCommitments => {
    if (secretPolynomial.length !== blindingPolynomial.length) {
        throw new Error(
            'Secret and blinding polynomials must have the same degree',
        );
    }

    return {
        commitments: secretPolynomial.map((coefficient, index) => {
            const blinding = blindingPolynomial[index];

            assertScalarInZq(coefficient, group.q);
            assertScalarInZq(blinding, group.q);

            return multiExponentiate(
                [
                    { base: group.g, exponent: coefficient },
                    { base: group.h, exponent: blinding },
                ],
                group.p,
            );
        }),
    };
};

/**
 * Derives indexed Pedersen share pairs from matching secret and blinding
 * polynomials.
 *
 * @param secretPolynomial Secret polynomial coefficients.
 * @param blindingPolynomial Blinding polynomial coefficients.
 * @param participantCount Total participant count.
 * @param q Prime-order subgroup order.
 * @returns Secret and blinding share pairs for `1..participantCount`.
 */
export const derivePedersenShares = (
    secretPolynomial: Polynomial,
    blindingPolynomial: Polynomial,
    participantCount: number,
    q: bigint,
): readonly PedersenShare[] => {
    if (secretPolynomial.length !== blindingPolynomial.length) {
        throw new Error(
            'Secret and blinding polynomials must have the same degree',
        );
    }

    if (!Number.isInteger(participantCount) || participantCount < 1) {
        throw new ThresholdViolationError(
            'Participant count must be a positive integer',
        );
    }

    const shares: PedersenShare[] = [];

    for (let index = 1; index <= participantCount; index += 1) {
        shares.push({
            index,
            secretValue: evaluatePolynomial(secretPolynomial, BigInt(index), q),
            blindingValue: evaluatePolynomial(
                blindingPolynomial,
                BigInt(index),
                q,
            ),
        });
    }

    return shares;
};

/**
 * Verifies a Pedersen share pair against the published commitments.
 *
 * @param share Indexed secret and blinding share pair.
 * @param commitments Published Pedersen commitments.
 * @param group Resolved group definition.
 * @returns `true` when the share pair matches the commitments.
 */
export const verifyPedersenShare = (
    share: PedersenShare,
    commitments: PedersenCommitments,
    group: CryptoGroup,
): boolean => {
    assertPositiveParticipantIndex(share.index);
    assertScalarInZq(share.secretValue, group.q);
    assertScalarInZq(share.blindingValue, group.q);
    commitments.commitments.forEach((commitment) =>
        assertInSubgroup(commitment, group.p, group.q),
    );

    return (
        multiExponentiate(
            [
                { base: group.g, exponent: share.secretValue },
                { base: group.h, exponent: share.blindingValue },
            ],
            group.p,
        ) ===
        evaluateCommitmentProduct(commitments.commitments, share.index, group)
    );
};
