import {
    InvalidScalarError,
    assertScalarInZq,
    assertThreshold,
    assertValidParticipantIndex,
    randomScalarInRange,
} from '../core/index.js';
import { encodePoint, multiplyBase } from '../core/ristretto.js';
import { resolveElgamalGroup } from '../elgamal/helpers.js';
import type { ElgamalGroupInput } from '../elgamal/types.js';

import {
    evaluatePolynomial,
    generatePolynomial,
    type Polynomial,
} from './polynomial.js';
import type { Share, ThresholdKeySet } from './types.js';

const createSharesFromPolynomial = (
    polynomial: Polynomial,
    participantCount: number,
    q: bigint,
): Share[] => {
    if (!Number.isInteger(participantCount) || participantCount < 1) {
        throw new InvalidScalarError(
            'Participant count must be a positive integer',
        );
    }

    const shares: Share[] = [];

    for (let index = 1; index <= participantCount; index += 1) {
        assertValidParticipantIndex(index, participantCount);
        shares.push({
            index,
            value: evaluatePolynomial(polynomial, BigInt(index), q),
        });
    }

    return shares;
};

/**
 * Splits a fresh secret into indexed Shamir shares and derives the threshold
 * public key for dealer-based threshold decryption.
 */
export const dealerKeyGen = (
    threshold: number,
    participantCount: number,
    group: ElgamalGroupInput,
): ThresholdKeySet => {
    const resolvedGroup = resolveElgamalGroup(group);

    assertThreshold(threshold, participantCount);

    const secret = randomScalarInRange(1n, resolvedGroup.q);
    const polynomial = generatePolynomial(secret, threshold, resolvedGroup.q);

    return {
        threshold,
        participantCount,
        publicKey: encodePoint(multiplyBase(secret)),
        shares: createSharesFromPolynomial(
            polynomial,
            participantCount,
            resolvedGroup.q,
        ),
        group: resolvedGroup,
    };
};

/**
 * Deterministically derives indexed shares from a caller-supplied polynomial.
 */
export const deriveSharesFromPolynomial = (
    polynomial: Polynomial,
    participantCount: number,
    q: bigint,
): readonly Share[] => {
    for (const coefficient of polynomial) {
        assertScalarInZq(coefficient, q);
    }

    return createSharesFromPolynomial(polynomial, participantCount, q);
};
