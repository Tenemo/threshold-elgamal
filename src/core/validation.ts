import { modPowP } from './bigint.js';
import {
    IndexOutOfRangeError,
    InvalidGroupElementError,
    InvalidScalarError,
    PlaintextDomainError,
    ThresholdViolationError,
} from './errors.js';

/** Returns `true` when the value is a non-identity element of the order-`q` subgroup. */
export const isInSubgroup = (value: bigint, p: bigint, q: bigint): boolean =>
    value > 1n && value < p - 1n && modPowP(value, q, p) === 1n;

/** Returns `true` when the value is the subgroup identity or a valid subgroup element. */
export const isInSubgroupOrIdentity = (
    value: bigint,
    p: bigint,
    q: bigint,
): boolean => value === 1n || isInSubgroup(value, p, q);

/**
 * Validates a one-based participant index against a fixed roster size.
 *
 * @throws {@link IndexOutOfRangeError} When the index or participant count is
 * not an integer, or when the index falls outside `1..participantCount`.
 */
export const assertValidParticipantIndex = (
    index: number,
    participantCount: number,
): void => {
    // Ceremony roster positions are tracked as 1-based integers. Threshold
    // arithmetic converts them to bigint only at the Lagrange boundary.
    if (!Number.isInteger(index) || !Number.isInteger(participantCount)) {
        throw new IndexOutOfRangeError('Participant indices must be integers');
    }

    if (participantCount < 1 || index < 1 || index > participantCount) {
        throw new IndexOutOfRangeError(
            `Participant index ${index} must be in the range 1..${participantCount}`,
        );
    }
};

/**
 * Validates a threshold `k` against a participant count `n`.
 *
 * @throws {@link ThresholdViolationError} When either input is not an integer
 * or when `k` falls outside `1..n`.
 */
export const assertThreshold = (
    threshold: number,
    participantCount: number,
): void => {
    if (!Number.isInteger(threshold) || !Number.isInteger(participantCount)) {
        throw new ThresholdViolationError(
            'Threshold and participant count must be integers',
        );
    }

    if (participantCount < 1 || threshold < 1 || threshold > participantCount) {
        throw new ThresholdViolationError(
            `Threshold ${threshold} must satisfy 1 <= threshold <= participantCount (${participantCount})`,
        );
    }
};

/**
 * Validates that a scalar belongs to `Z_q`.
 *
 * @throws {@link InvalidScalarError} When the value is outside `0..q-1`.
 */
export const assertScalarInZq = (value: bigint, q: bigint): void => {
    if (value < 0n || value >= q) {
        throw new InvalidScalarError(
            `Scalar ${value} is outside the valid Z_q range`,
        );
    }
};

/**
 * Validates the plaintext domain and caller-supplied bound for additive
 * ElGamal.
 *
 * @throws {@link InvalidScalarError} When `bound` is outside `0..q-1`.
 * @throws {@link PlaintextDomainError} When `value` is outside `0..bound`.
 */
export const assertPlaintextAdditive = (
    value: bigint,
    bound: bigint,
    q: bigint,
): void => {
    if (bound < 0n || bound >= q) {
        throw new InvalidScalarError(
            'Additive plaintext bound must be in the range 0..q-1',
        );
    }

    if (value < 0n || value > bound) {
        throw new PlaintextDomainError(
            `Additive mode requires plaintext values in the range 0..${bound}`,
        );
    }
};

/**
 * Validates that a value is a non-identity element of the prime-order subgroup.
 *
 * @throws {@link InvalidGroupElementError} When the value is outside the
 * subgroup.
 */
export const assertInSubgroup = (value: bigint, p: bigint, q: bigint): void => {
    if (!isInSubgroup(value, p, q)) {
        throw new InvalidGroupElementError(
            'Element is not in the prime-order subgroup',
        );
    }
};

/**
 * Validates that a value is either the subgroup identity or a non-identity
 * subgroup element.
 *
 * @throws {@link InvalidGroupElementError} When the value is outside the
 * subgroup-or-identity domain.
 */
export const assertInSubgroupOrIdentity = (
    value: bigint,
    p: bigint,
    q: bigint,
): void => {
    if (!isInSubgroupOrIdentity(value, p, q)) {
        throw new InvalidGroupElementError(
            'Element is not in the prime-order subgroup or its identity',
        );
    }
};

/**
 * Validates a public key as a non-identity prime-order subgroup element.
 *
 * @throws {@link InvalidGroupElementError} When the value is not a valid
 * subgroup public key.
 */
export const assertValidPublicKey = (
    value: bigint,
    p: bigint,
    q: bigint,
): void => {
    if (!isInSubgroup(value, p, q)) {
        throw new InvalidGroupElementError(
            'Public key must be a valid prime-order subgroup element',
        );
    }
};
