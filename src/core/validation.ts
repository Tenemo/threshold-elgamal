import { modPowP } from './bigint.js';
import {
    InvalidGroupElementError,
    InvalidScalarError,
    PlaintextDomainError,
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
