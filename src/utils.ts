import crypto from 'crypto';

import type { EncryptedMessage } from './types';

/**
 * Returns a random bigint in the given range.
 * @param {bigint} min Minimum value (included).
 * @param {bigint} max Maximum value (excluded).
 * @returns {bigint}
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
 * Performs homomorphic multiplication of two encrypted values.
 * @param value1 The first encrypted value.
 * @param value2 The second encrypted value.
 * @param prime The prime number used in the ElGamal cryptosystem.
 * @returns The result of the homomorphic multiplication as a new EncryptedMessage.
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

type GCDResult = {
    x: bigint;
    y: bigint;
    gcd: bigint;
};

const extendedGCD = (a: bigint, b: bigint): GCDResult => {
    if (b === 0n) {
        return { x: 1n, y: 0n, gcd: a };
    } else {
        const { x: x1, y: y1, gcd } = extendedGCD(b, a % b);
        return { x: y1, y: x1 - (a / b) * y1, gcd };
    }
};

export const modInverse = (a: bigint, modulus: bigint): bigint => {
    const { x, gcd } = extendedGCD(a, modulus);
    if (gcd !== 1n) {
        throw new Error('The modular inverse does not exist.');
    } else {
        // JavaScript's % operator can return a negative value. Since we're working
        // in a modular arithmetic context, we're interested in the positive equivalent.
        return ((x % modulus) + modulus) % modulus;
    }
};
