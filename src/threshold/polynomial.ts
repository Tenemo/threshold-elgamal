import {
    InvalidScalarError,
    ThresholdViolationError,
    modQ,
    randomScalarInRange,
} from '../core/index.js';

/** Coefficients for `f(x) = a0 + a1*x + ... + a{k-1}*x^{k-1}` over `Z_q`. */
export type Polynomial = readonly bigint[];

/**
 * Generates a random degree-`threshold - 1` polynomial over `Z_q`.
 *
 * The constant coefficient is the shared secret. All non-constant coefficients
 * are sampled from `1..q-1` so the generated polynomial has the requested
 * degree exactly.
 *
 * @param secret Secret value used as the constant coefficient.
 * @param threshold Reconstruction threshold `k`.
 * @param q Prime-order subgroup order.
 * @returns Polynomial coefficients in ascending order.
 */
export const generatePolynomial = (
    secret: bigint,
    threshold: number,
    q: bigint,
): Polynomial => {
    if (!Number.isInteger(threshold) || threshold < 1) {
        throw new ThresholdViolationError(
            'Threshold must be a positive integer',
        );
    }

    if (q <= 1n) {
        throw new InvalidScalarError(
            'Polynomial modulus q must be greater than 1',
        );
    }

    const coefficients: bigint[] = [modQ(secret, q)];

    for (let index = 1; index < threshold; index += 1) {
        coefficients.push(randomScalarInRange(1n, q));
    }

    return coefficients;
};

/**
 * Evaluates a polynomial at `x` with Horner's method over `Z_q`.
 *
 * @param polynomial Polynomial coefficients in ascending order.
 * @param x Evaluation point.
 * @param q Prime-order subgroup order.
 * @returns `f(x) mod q`.
 */
export const evaluatePolynomial = (
    polynomial: Polynomial,
    x: bigint,
    q: bigint,
): bigint => {
    let result = 0n;

    for (let index = polynomial.length - 1; index >= 0; index -= 1) {
        result = modQ(modQ(result * x, q) + polynomial[index], q);
    }

    return result;
};
