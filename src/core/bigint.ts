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

export const mod = (value: bigint, modulus: bigint): bigint => {
    assertPositiveModulus(modulus);
    return normalize(value, modulus);
};

export const modP = (value: bigint, p: bigint): bigint => mod(value, p);
export const modQ = (value: bigint, q: bigint): bigint => mod(value, q);

export const modInvP = (value: bigint, p: bigint): bigint => {
    assertPositiveModulus(p);
    return modInv(modP(value, p), p);
};

export const modInvQ = (value: bigint, q: bigint): bigint => {
    assertPositiveModulus(q);
    return modInv(modQ(value, q), q);
};

export const modPowP = (base: bigint, exponent: bigint, p: bigint): bigint => {
    assertPositiveModulus(p);
    if (exponent < 0n) {
        throw new InvalidScalarError('Exponent must be non-negative');
    }
    return modPow(modP(base, p), exponent, p);
};
