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

export const assertValidParticipantIndex = (
    index: number,
    participantCount: number,
): void => {
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

export const assertPlaintextMultiplicative = (value: bigint): void => {
    if (value <= 0n) {
        throw new PlaintextDomainError(
            'Multiplicative mode requires plaintext values greater than 0',
        );
    }
};

export const assertPlaintextAdditive = (value: bigint, bound: bigint): void => {
    if (bound < 0n) {
        throw new InvalidScalarError('Additive plaintext bound must be >= 0');
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
