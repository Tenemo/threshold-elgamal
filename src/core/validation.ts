import { modPowP } from './bigint.js';
import {
    IndexOutOfRangeError,
    InvalidGroupElementError,
    InvalidScalarError,
    PlaintextDomainError,
    ThresholdViolationError,
} from './errors.js';

export const isInSubgroup = (value: bigint, p: bigint, q: bigint): boolean =>
    value > 1n && value < p - 1n && modPowP(value, q, p) === 1n;

export const isInSubgroupOrIdentity = (
    value: bigint,
    p: bigint,
    q: bigint,
): boolean => value === 1n || isInSubgroup(value, p, q);

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

export const assertScalarInZq = (value: bigint, q: bigint): void => {
    if (value < 0n || value >= q) {
        throw new InvalidScalarError(
            `Scalar ${value} is outside the valid Z_q range`,
        );
    }
};

export const assertPlaintextMultiplicative = (
    value: bigint,
    p: bigint,
): void => {
    if (value <= 0n || value >= p) {
        throw new PlaintextDomainError(
            'Multiplicative mode requires plaintext values in the range 1..p-1',
        );
    }
};

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

export const assertInSubgroup = (value: bigint, p: bigint, q: bigint): void => {
    if (!isInSubgroup(value, p, q)) {
        throw new InvalidGroupElementError(
            'Element is not in the prime-order subgroup',
        );
    }
};

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
