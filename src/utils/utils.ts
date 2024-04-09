import { GROUPS } from '../constants';
import type { EncryptedMessage } from '../types';

/**
 * Generates a random BigInt of exactly the specified number of bits.
 * The function calculates the required number of hexadecimal digits to represent
 * the given number of bits. It ensures the most significant bit is always set,
 * guaranteeing the BigInt has the exact bit length specified. The remaining
 * bits are filled with random values to complete the desired bit length.
 *
 * @param {number} bits The exact bit length for the generated BigInt.
 * @returns {bigint} A random BigInt of exactly the specified bit length.
 *
 * @example
 * // Generates a random BigInt of exactly 128 bits
 * const randomBigInt = generateRandomBigIntFromBits(128);
 * console.log(randomBigInt);
 */
export const randomBigint = (bits: number): bigint => {
    // Ensure bits is positive and greater than zero to avoid infinite loop
    if (bits <= 0) {
        throw new RangeError('Bit length must be greater than 0');
    }

    // Calculate the number of hexadecimal digits needed
    const hexDigits = Math.ceil(bits / 4);

    // The first hex digit must be between 8 and F (inclusive) to ensure the MSB is set
    const firstDigit = (8 + Math.floor(Math.random() * 8)).toString(16);

    // Generate the remaining hex digits randomly
    const remainingDigits = Array(hexDigits - 1)
        .fill(0)
        .map(() => Math.floor(Math.random() * 16).toString(16))
        .join('');

    // Combine, convert to BigInt, and return
    return BigInt(`0x${firstDigit}${remainingDigits}`);
};

/**
 * Retrieves the group parameters for a given prime bit length.
 *
 * @param {2048 | 3072 | 4096} primeBits - The bit length of the prime modulus (2048, 3072, or 4096).
 * @returns {Object} The group parameters including prime and generator.
 */
export const getGroup = (
    primeBits: 2048 | 3072 | 4096 = 2048,
): { prime: bigint; generator: bigint } => {
    switch (primeBits) {
        case 2048:
            return GROUPS.ffdhe2048;
        case 3072:
            return GROUPS.ffdhe3072;
        case 4096:
            return GROUPS.ffdhe4096;
        default:
            throw new Error('Unsupported bit length');
    }
};

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
 * @param {bigint} prime - The prime modulus used in the encryption system. Defaults to the 2048-bit group prime.
 * @returns {EncryptedMessage} The result of the multiplication, as a new encrypted message.
 */
export const multiplyEncryptedValues = (
    value1: EncryptedMessage,
    value2: EncryptedMessage,
    prime: bigint = getGroup().prime,
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
