/**
 * Shared invariant checks for points, scalars, thresholds, and participant
 * indices.
 *
 * These helpers sit underneath every higher-level subsystem: proofs, VSS, DKG,
 * ballot handling, and the full ceremony verifier all route through them.
 */
import {
    IndexOutOfRangeError,
    InvalidGroupElementError,
    InvalidScalarError,
    PlaintextDomainError,
    ThresholdViolationError,
} from './errors';
import { decodePoint, RISTRETTO_ORDER } from './ristretto';

/**
 * Returns `true` when the value is a canonical non-identity Ristretto point.
 *
 * This is the predicate used for public keys and most commitment elements.
 */
export const isInSubgroup = (value: string): boolean => {
    try {
        return !decodePoint(value).is0();
    } catch {
        return false;
    }
};

/**
 * Returns `true` when the value is a canonical Ristretto point, including the
 * identity element.
 *
 * This variant is used for ciphertext components and transcript values that
 * are allowed to land on the identity.
 */
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
 * Derives the supported honest-majority threshold `ceil(n / 2)`.
 *
 * This is the threshold policy used by the package's DKG and full voting flow.
 * Callers do not choose a custom `k`; the verifier derives it from the
 * accepted registration roster.
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
 * Validates that the supplied threshold matches the library's GJKR
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

/**
 * Validates a 1-based participant index without assuming a fixed participant
 * count.
 *
 * The package consistently numbers trustees and voters from `1`.
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
 * Validates a 1-based participant index against a fixed participant count.
 *
 * This is the usual check for published payloads that already sit inside a
 * frozen roster.
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
 * Validates that a value is a canonical non-identity Ristretto point.
 *
 * This is the assertion form of {@link isInSubgroup}.
 */
export const assertInSubgroup = (value: string): void => {
    if (!isInSubgroup(value)) {
        throw new InvalidGroupElementError(
            'Element is not a valid non-identity Ristretto point',
        );
    }
};

/**
 * Validates that a value is a canonical Ristretto point, including identity.
 *
 * This is the assertion form of {@link isInSubgroupOrIdentity}.
 */
export const assertInSubgroupOrIdentity = (value: string): void => {
    if (!isInSubgroupOrIdentity(value)) {
        throw new InvalidGroupElementError(
            'Element is not a valid Ristretto point',
        );
    }
};

/**
 * Validates a public key as a canonical non-identity Ristretto point.
 *
 * Public keys, verification keys, and commitment generators all route through
 * this helper.
 */
export const assertValidPublicKey = (value: string): void => {
    if (!isInSubgroup(value)) {
        throw new InvalidGroupElementError(
            'Public key must be a valid non-identity Ristretto point',
        );
    }
};
