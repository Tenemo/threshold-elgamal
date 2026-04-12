import {
    IndexOutOfRangeError,
    InvalidGroupElementError,
    InvalidScalarError,
    PlaintextDomainError,
    ThresholdViolationError,
} from './errors';
import { decodePoint, RISTRETTO_ORDER } from './ristretto';

/** Returns `true` when the value is a non-identity valid Ristretto point. */
export const isInSubgroup = (value: string): boolean => {
    try {
        return !decodePoint(value).is0();
    } catch {
        return false;
    }
};

/** Returns `true` when the value is a valid Ristretto point, including identity. */
export const isInSubgroupOrIdentity = (value: string): boolean => {
    try {
        decodePoint(value);
        return true;
    } catch {
        return false;
    }
};

/**
 * Validates that a scalar belongs to `Z_q`.
 *
 * @throws {@link InvalidScalarError} When the value is outside `0..q-1`.
 */
export const assertScalarInZq = (
    value: bigint,
    q: bigint = RISTRETTO_ORDER,
): void => {
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
export const assertAdditiveBound = (bound: bigint, q: bigint): void => {
    if (bound < 0n || bound >= q) {
        throw new InvalidScalarError(
            'Additive plaintext bound must be in the range 0..q-1',
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
    assertAdditiveBound(bound, q);

    if (value < 0n || value > bound) {
        throw new PlaintextDomainError(
            `Additive mode requires plaintext values in the range 0..${bound}`,
        );
    }
};

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
 * Derives the shipped GJKR honest-majority threshold `ceil(n / 2)`.
 *
 * For odd `n` this matches the usual strict-majority value. For even `n` the
 * shipped protocol uses the maximal honest-majority instantiation proved for
 * GJKR, which yields `k = n / 2`.
 */
export const majorityThreshold = (participantCount: number): number => {
    if (!Number.isInteger(participantCount) || participantCount < 1) {
        throw new ThresholdViolationError(
            'Participant count must be a positive integer',
        );
    }

    return Math.ceil(participantCount / 2);
};

/**
 * Validates that the supplied threshold matches the shipped GJKR
 * honest-majority policy.
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

    const expectedThreshold = majorityThreshold(participantCount);
    if (threshold !== expectedThreshold) {
        throw new ThresholdViolationError(
            `Supported distributed threshold must equal ceil(n / 2) (expected ${expectedThreshold} for n = ${participantCount})`,
        );
    }

    return threshold;
};

/** Validates a 1-based participant index without assuming a fixed count. */
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

/** Validates a 1-based participant index for a fixed participant count. */
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

/** Validates that a value is a non-identity valid Ristretto point. */
export const assertInSubgroup = (value: string): void => {
    if (!isInSubgroup(value)) {
        throw new InvalidGroupElementError(
            'Element is not a valid non-identity Ristretto point',
        );
    }
};

/** Validates that a value is a valid Ristretto point, including identity. */
export const assertInSubgroupOrIdentity = (value: string): void => {
    if (!isInSubgroupOrIdentity(value)) {
        throw new InvalidGroupElementError(
            'Element is not a valid Ristretto point',
        );
    }
};

/** Validates a public key as a non-identity Ristretto point. */
export const assertValidPublicKey = (value: string): void => {
    if (!isInSubgroup(value)) {
        throw new InvalidGroupElementError(
            'Public key must be a valid non-identity Ristretto point',
        );
    }
};
