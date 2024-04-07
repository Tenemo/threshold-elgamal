import randomBigint from 'random-bigint';

import type { EncryptedMessage } from './types';

/**
 * Generates a random bigint within a specified range.
 * @param {bigint} min - The minimum value (inclusive).
 * @param {bigint} max - The maximum value (exclusive).
 * @returns {bigint} A random bigint within the specified range.
 */
export const getRandomBigIntegerInRange = (
    min: bigint,
    max: bigint,
): bigint => {
    const range = max - min + 1n;
    // Determine the number of bits needed for the range
    const bitsNeeded = range.toString(2).length;
    // Generate a random bigint within the calculated bits
    let num = randomBigint(bitsNeeded);
    // Adjust the number to our range
    num = num % range;
    // Add the minimum to align with our desired range
    return min + num;
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
    const polynomial = [getRandomBigIntegerInRange(2n, prime - 1n)]; // constant term is the "master" private key
    for (let i = 1; i < threshold; i++) {
        polynomial.push(getRandomBigIntegerInRange(0n, prime - 1n)); // random coefficients
    }
    return polynomial;
};
