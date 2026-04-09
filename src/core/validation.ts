import {
    assertAdditiveBound as assertSharedAdditiveBound,
    assertAdditivePlaintext,
} from './additive-validation.js';
import { modPowP } from './bigint.js';
import {
    IndexOutOfRangeError,
    InvalidGroupElementError,
    InvalidScalarError,
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
 * Validates the caller-supplied additive plaintext bound.
 *
 * @throws {@link InvalidScalarError} When `bound` is outside `0..q-1`.
 */
export const assertAdditiveBound = (bound: bigint, q: bigint): void =>
    assertSharedAdditiveBound(bound, q);

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
): void => assertAdditivePlaintext(value, bound, q);

/**
 * Validates threshold parameters for `k`-of-`n` protocols.
 *
 * @throws {@link ThresholdViolationError} When the inputs are not integers or
 * `threshold` does not satisfy `1 <= k <= n`.
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

    if (participantCount < 1) {
        throw new ThresholdViolationError(
            'Participant count must be a positive integer',
        );
    }

    if (threshold < 1 || threshold > participantCount) {
        throw new ThresholdViolationError(
            `Threshold ${threshold} must satisfy 1 <= k <= n (n = ${participantCount})`,
        );
    }
};

/**
 * Derives the minimum strict-majority threshold `floor(n / 2) + 1`.
 *
 * @param participantCount Total participant count `n`.
 * @returns Minimum supported reconstruction threshold `k`.
 *
 * @throws {@link ThresholdViolationError} When `participantCount` is not a
 * positive integer.
 */
export const majorityThreshold = (participantCount: number): number => {
    if (!Number.isInteger(participantCount) || participantCount < 1) {
        throw new ThresholdViolationError(
            'Participant count must be a positive integer',
        );
    }

    return Math.floor(participantCount / 2) + 1;
};

/**
 * Validates that the supplied threshold satisfies the shipped strict-majority
 * policy.
 *
 * @param threshold Claimed reconstruction threshold.
 * @param participantCount Total participant count `n`.
 * @returns The validated reconstruction threshold.
 *
 * @throws {@link ThresholdViolationError} When the threshold falls outside the
 * supported strict-majority policy.
 */
export const assertMajorityThreshold = (
    threshold: number,
    participantCount: number,
): number => {
    assertThreshold(threshold, participantCount);

    if (participantCount < 3) {
        throw new ThresholdViolationError(
            'Distributed threshold workflows require at least three participants',
        );
    }

    const minimumThreshold = majorityThreshold(participantCount);
    const maximumThreshold = participantCount - 1;
    if (threshold < minimumThreshold || threshold > maximumThreshold) {
        throw new ThresholdViolationError(
            `Supported distributed threshold must satisfy floor(n / 2) + 1 <= k <= n - 1 (minimum ${minimumThreshold}, maximum ${maximumThreshold} for n = ${participantCount})`,
        );
    }

    return threshold;
};

/**
 * Validates a 1-based participant index without assuming a fixed participant
 * count.
 *
 * @throws {@link IndexOutOfRangeError} When `index` is not a positive integer.
 */
export const assertPositiveParticipantIndex = (index: number): void => {
    if (!Number.isInteger(index)) {
        throw new IndexOutOfRangeError('Participant index must be an integer');
    }

    if (index < 1) {
        throw new IndexOutOfRangeError(
            'Participant index must be a positive integer',
        );
    }
};

/**
 * Validates a 1-based participant index for a fixed participant count.
 *
 * @throws {@link IndexOutOfRangeError} When the inputs are not integers or
 * `index` is outside `1..participantCount`.
 */
export const assertValidParticipantIndex = (
    index: number,
    participantCount: number,
): void => {
    if (!Number.isInteger(index) || !Number.isInteger(participantCount)) {
        throw new IndexOutOfRangeError(
            'Participant index and count must be integers',
        );
    }

    if (participantCount < 1) {
        throw new IndexOutOfRangeError(
            'Participant count must be a positive integer',
        );
    }

    if (index < 1 || index > participantCount) {
        throw new IndexOutOfRangeError(
            `Participant index ${index} must satisfy 1 <= j <= n (n = ${participantCount})`,
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
