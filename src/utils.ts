import crypto from 'crypto';

import type { EncryptedMessage } from './types';

/**
 * Generates a random bigint within a specified range.
 * @param {bigint} min - The minimum value (inclusive).
 * @param {bigint} max - The maximum value (exclusive).
 * @returns {bigint} A random bigint within the specified range.
 */
export const getRandomBigInteger = (min: bigint, max: bigint): bigint => {
    const range = max - min;
    const rangeBytes = Math.ceil(range.toString(2).length / 8);
    let randomBigInt;

    do {
        // Generate random bytes with the length of the range
        const buffer = crypto.randomBytes(rangeBytes);
        const hex = '0x' + buffer.toString('hex');
        // Offset the result by the minimum value
        randomBigInt = (BigInt(hex) % range) + min;
    } while (randomBigInt >= max);

    return randomBigInt;
};

/**
 * Performs homomorphic multiplication on two encrypted values, allowing for encrypted arithmetic operations.
 * @param {EncryptedMessage} value1 - The first encrypted value.
 * @param {EncryptedMessage} value2 - The second encrypted value.
 * @param {bigint} prime - The prime modulus used in the encryption system.
 * @returns {EncryptedMessage} The result of the multiplication, as a new encrypted message.
 */
export const multiplyEncryptedValues = (
    value1: EncryptedMessage,
    value2: EncryptedMessage,
    prime: bigint,
): EncryptedMessage => {
    const c1Multiplied = (value1.c1 * value2.c1) % prime;
    const c2Multiplied = (value1.c2 * value2.c2) % prime;

    return { c1: c1Multiplied, c2: c2Multiplied };
};

/**
 * Calculates the result of raising a base to a given exponent, modulo a specified modulus.
 * @param {bigint} base - The base value.
 * @param {bigint} exponent - The exponent value.
 * @param {bigint} modulus - The modulus for the operation.
 * @returns {bigint} The result of (base^exponent) mod modulus.
 */
export const modPow = (
    base: bigint,
    exponent: bigint,
    modulus: bigint,
): bigint => {
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
        if (exponent % 2n === 1n) result = (result * base) % modulus;
        exponent = exponent >> 1n;
        base = (base * base) % modulus;
    }
    return result;
};

const extendedGCD = (
    a: bigint,
    b: bigint,
): {
    x: bigint;
    y: bigint;
    gcd: bigint;
} => {
    if (b === 0n) {
        return { x: 1n, y: 0n, gcd: a };
    } else {
        const { x: x1, y: y1, gcd } = extendedGCD(b, a % b);
        return { x: y1, y: x1 - (a / b) * y1, gcd };
    }
};

/**
 * Finds the modular inverse of a value `a` modulo `modulus`, such that (a * inverse) % modulus = 1.
 * @param {bigint} a - The value to find the modular inverse for.
 * @param {bigint} modulus - The modulus of the modular arithmetic system.
 * @returns {bigint} The modular inverse of `a`.
 * @throws {Error} Throws an error if the modular inverse does not exist.
 */
export const modInverse = (a: bigint, modulus: bigint): bigint => {
    const { x, gcd } = extendedGCD(a, modulus);
    if (gcd !== 1n) {
        throw new Error('The modular inverse does not exist.');
    } else {
        // Return the positive value of the modular inverse
        return ((x % modulus) + modulus) % modulus;
    }
};

/**
 * Generates a random polynomial of a specified degree, to be used in Shamir's Secret Sharing scheme.
 * The polynomial is of the form f(x) = a0 + a1*x + a2*x^2 + ... + a_{threshold-1}*x^{threshold-1},
 * where a0 is the "master" secret, and the rest of the coefficients are randomly chosen.
 * @param {number} threshold - The degree of the polynomial (also, the number of shares required to reconstruct the secret).
 * @param {bigint} prime - The prime modulus used in the system, to ensure operations are performed in a finite field.
 * @returns {bigint[]} An array representing the polynomial coefficients `[a0, a1, ..., a_{threshold-1}]`.
 */
export const generatePolynomial = (
    threshold: number,
    prime: bigint,
): bigint[] => {
    const polynomial = [getRandomBigInteger(2n, prime - 1n)]; // constant term is the "master" private key
    for (let i = 1; i < threshold; i++) {
        polynomial.push(getRandomBigInteger(0n, prime - 1n)); // random coefficients
    }
    return polynomial;
};
