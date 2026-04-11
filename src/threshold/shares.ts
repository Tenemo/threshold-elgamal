import {
    InvalidScalarError,
    assertScalarInZq,
    assertValidParticipantIndex,
} from '../core/index.js';

import { evaluatePolynomial, type Polynomial } from './polynomial.js';
import type { Share } from './types.js';

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
