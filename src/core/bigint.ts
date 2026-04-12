import { InvalidScalarError } from './errors.js';

const assertPositiveModulus = (modulus: bigint): void => {
    if (modulus <= 0n) {
        throw new InvalidScalarError('Modulus must be positive');
    }
};

const normalize = (value: bigint, modulus: bigint): bigint => {
    const result = value % modulus;
    return result >= 0n ? result : result + modulus;
};

const extendedGcd = (
    a: bigint,
    b: bigint,
): { gcd: bigint; x: bigint; y: bigint } => {
    let oldR = a;
    let r = b;
    let oldS = 1n;
    let s = 0n;
    let oldT = 0n;
    let t = 1n;

    while (r !== 0n) {
        const quotient = oldR / r;
        [oldR, r] = [r, oldR - quotient * r];
        [oldS, s] = [s, oldS - quotient * s];
        [oldT, t] = [t, oldT - quotient * t];
    }

    return { gcd: oldR, x: oldS, y: oldT };
};

const modInv = (value: bigint, modulus: bigint): bigint => {
    const { gcd, x } = extendedGcd(value, modulus);
    if (gcd !== 1n) {
        throw new InvalidScalarError('Modular inverse does not exist');
    }

    return normalize(x, modulus);
};

const modPow = (base: bigint, exponent: bigint, modulus: bigint): bigint => {
    if (modulus === 1n) {
        return 0n;
    }

    let result = 1n;
    let currentBase = normalize(base, modulus);
    let currentExponent = exponent;

    while (currentExponent > 0n) {
        if ((currentExponent & 1n) === 1n) {
            result = normalize(result * currentBase, modulus);
        }

        currentExponent >>= 1n;
        if (currentExponent > 0n) {
            currentBase = normalize(currentBase * currentBase, modulus);
        }
    }

    return result;
};

/**
 * Reduces a value into the canonical range `0..modulus-1`.
 *
 * @throws {@link InvalidScalarError} When `modulus` is not positive.
 */
export const mod = (value: bigint, modulus: bigint): bigint => {
    assertPositiveModulus(modulus);
    return normalize(value, modulus);
};

/**
 * Reduces a value into the range `0..p-1`.
 *
 * @throws {@link InvalidScalarError} When `p` is not positive.
 */
const modP = (value: bigint, p: bigint): bigint => mod(value, p);
/**
 * Reduces a value into the range `0..q-1`.
 *
 * @throws {@link InvalidScalarError} When `q` is not positive.
 */
export const modQ = (value: bigint, q: bigint): bigint => mod(value, q);

/**
 * Computes the multiplicative inverse of a value modulo `q`.
 *
 * @throws {@link InvalidScalarError} When `q` is not positive or the inverse
 * does not exist.
 */
export const modInvQ = (value: bigint, q: bigint): bigint => {
    assertPositiveModulus(q);
    return modInv(modQ(value, q), q);
};

/**
 * Computes `base^exponent mod p` for non-negative exponents.
 *
 * @throws {@link InvalidScalarError} When `p` is not positive or `exponent` is
 * negative.
 */
export const modPowP = (base: bigint, exponent: bigint, p: bigint): bigint => {
    assertPositiveModulus(p);
    if (exponent < 0n) {
        throw new InvalidScalarError('Exponent must be non-negative');
    }
    return normalize(modPow(modP(base, p), exponent, p), p);
};
