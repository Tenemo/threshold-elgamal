import { assertCanonicalRistrettoGroup } from '../core/group-invariants.js';
import {
    assertInSubgroup,
    assertPositiveParticipantIndex,
    assertScalarInZq,
    InvalidPayloadError,
    ThresholdViolationError,
    type CryptoGroup,
} from '../core/index.js';
import {
    decodePoint,
    encodePoint,
    multiplyBase,
    pointAdd,
    pointMultiply,
} from '../core/ristretto.js';
import {
    evaluatePolynomial,
    type Polynomial,
} from '../threshold/polynomial.js';

import { evaluateCommitmentProduct } from './commitment-product.js';
import type { PedersenCommitments, PedersenShare } from './types.js';

const pedersenPolynomialLengthError =
    'Secret and blinding polynomials must have the same degree';

/**
 * Computes Pedersen commitments for matching secret and blinding polynomials.
 */
export const generatePedersenCommitments = (
    secretPolynomial: readonly bigint[],
    blindingPolynomial: readonly bigint[],
    group: CryptoGroup,
): PedersenCommitments => {
    assertCanonicalRistrettoGroup(group, 'Pedersen commitment group');

    if (secretPolynomial.length !== blindingPolynomial.length) {
        throw new InvalidPayloadError(pedersenPolynomialLengthError);
    }

    const h = decodePoint(group.h, 'Pedersen generator');

    return {
        commitments: secretPolynomial.map((coefficient, index) => {
            const blinding = blindingPolynomial[index];

            assertScalarInZq(coefficient, group.q);
            assertScalarInZq(blinding, group.q);

            return encodePoint(
                pointAdd(multiplyBase(coefficient), pointMultiply(h, blinding)),
            );
        }),
    };
};

/**
 * Derives indexed Pedersen share pairs from matching secret and blinding
 * polynomials.
 */
export const derivePedersenShares = (
    secretPolynomial: Polynomial,
    blindingPolynomial: Polynomial,
    participantCount: number,
    q: bigint,
): readonly PedersenShare[] => {
    if (secretPolynomial.length !== blindingPolynomial.length) {
        throw new InvalidPayloadError(pedersenPolynomialLengthError);
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
 */
export const verifyPedersenShare = (
    share: PedersenShare,
    commitments: PedersenCommitments,
    group: CryptoGroup,
): boolean => {
    assertCanonicalRistrettoGroup(group, 'Pedersen verification group');
    assertPositiveParticipantIndex(share.index);
    assertScalarInZq(share.secretValue, group.q);
    assertScalarInZq(share.blindingValue, group.q);
    commitments.commitments.forEach((commitment) =>
        assertInSubgroup(commitment),
    );

    const h = decodePoint(group.h, 'Pedersen generator');
    const expected = pointAdd(
        multiplyBase(share.secretValue),
        pointMultiply(h, share.blindingValue),
    );

    return expected.equals(
        decodePoint(
            evaluateCommitmentProduct(
                commitments.commitments,
                share.index,
                group,
            ),
        ),
    );
};
