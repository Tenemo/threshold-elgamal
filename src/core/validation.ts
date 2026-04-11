import {
    IndexOutOfRangeError,
    InvalidGroupElementError,
    InvalidScalarError,
    PlaintextDomainError,
    ThresholdViolationError,
} from './errors.js';
import { decodePoint, RISTRETTO_ORDER } from './ristretto.js';

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
 * Derives the minimum strict-majority threshold `floor(n / 2) + 1`.
 *
 * This helper remains available for callers that intentionally want a
 * strict-majority policy. It is not the only distributed threshold policy
 * supported by the shipped manifest and DKG workflows.
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
 * Validates that the supplied threshold satisfies a strict-majority policy.
 *
 * This helper remains available for callers that intentionally want the older
 * strict-majority range. The shipped manifest and DKG workflows now accept the
 * broader distributed range `1 <= k <= n` for `n >= 3`.
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
