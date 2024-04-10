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

/**
 * Serializes an encrypted message into an object with string representations of its components.
 * This function is useful for converting the bigint components of an encrypted message into
 * strings, making them easier to store or transmit as JSON, for instance.
 *
 * @param {EncryptedMessage} message - The encrypted message to be serialized. It should have two bigint properties: `c1` and `c2`.
 * @returns {{ c1: string; c2: string }} An object containing the `c1` and `c2` components of the message as strings.
 *
 * @example
 * // An example encrypted message
 * const encryptedMessage = { c1: BigInt('1234567890123456789012345678901234567890'), c2: BigInt('0987654321098765432109876543210987654321') };
 * const serializedMessage = serializeEncryptedMessage(encryptedMessage);
 * console.log(serializedMessage); // Output: { c1: "1234567890123456789012345678901234567890", c2: "0987654321098765432109876543210987654321" }
 */
export const serializeEncryptedMessage = (
    message: EncryptedMessage,
): {
    c1: string;
    c2: string;
} => ({ c1: message.c1.toString(), c2: message.c2.toString() });

/**
 * Deserializes an object containing string representations of an encrypted message's components
 * back into an `EncryptedMessage` with bigint components. This is useful for reconstructing
 * encrypted messages from their stringified forms, such as when retrieving them from JSON data.
 *
 * @param {{ c1: string; c2: string }} message - An object containing the `c1` and `c2` components of the message as strings.
 * @returns {EncryptedMessage} The deserialized encrypted message with `c1` and `c2` as bigints.
 *
 * @example
 * // An example serialized message
 * const serializedMessage = { c1: "1234567890123456789012345678901234567890", c2: "0987654321098765432109876543210987654321" };
 * const encryptedMessage = deserializeEncryptedMessage(serializedMessage);
 * console.log(encryptedMessage); // Output: { c1: 1234567890123456789012345678901234567890n, c2: 0987654321098765432109876543210987654321n }
 */
export const deserializeEncryptedMessage = (message: {
    c1: string;
    c2: string;
}): EncryptedMessage => ({ c1: BigInt(message.c1), c2: BigInt(message.c2) });
