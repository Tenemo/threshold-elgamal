import { GROUPS } from './constants';
import type { EncryptedMessage, KeyShare } from './types';
import { modPow, modInverse, generatePolynomial } from './utils';

/**
 * Retrieves the group parameters for a given prime bit length.
 *
 * @param {2048 | 3072 | 4096} primeBits - The bit length of the prime modulus (2048, 3072, or 4096).
 * @returns {Object} The group parameters including prime and generator.
 */
const getGroup = (
    primeBits: 2048 | 3072 | 4096,
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
 * Evaluates a polynomial at a given point using modular arithmetic.
 *
 * @param {bigint[]} polynomial - The coefficients of the polynomial.
 * @param {number} x - The point at which to evaluate the polynomial.
 * @param {bigint} prime - The prime modulus.
 * @returns {bigint} The result of the polynomial evaluation.
 */
const evaluatePolynomial = (
    polynomial: bigint[],
    x: number,
    prime: bigint,
): bigint => {
    let result = 0n;
    for (let i = 0; i < polynomial.length; i++) {
        result =
            (result + polynomial[i] * modPow(BigInt(x), BigInt(i), prime)) %
            prime;
    }
    return result;
};

/**
 * Generates key shares for a threshold ElGamal cryptosystem.
 *
 * @param {number} n - The total number of key shares.
 * @param {number} threshold - The minimum number of key shares required for decryption.
 * @param {2048 | 3072 | 4096} primeBits - The bit length of the prime modulus (default: 2048).
 * @returns {KeyShare[]} An array of key shares, each containing a private and public key share.
 */
export const generateKeyShares = (
    n: number,
    threshold: number,
    primeBits: 2048 | 3072 | 4096 = 2048,
): KeyShare[] => {
    const group = getGroup(primeBits);
    const prime = group.prime;
    const generator = group.generator;

    const polynomial = generatePolynomial(threshold, prime);
    const keyShares = [];

    for (let i = 1; i <= n; i++) {
        const privateKeyShare = evaluatePolynomial(polynomial, i, prime);
        const publicKeyShare = modPow(generator, privateKeyShare, prime);
        keyShares.push({ privateKeyShare, publicKeyShare });
    }

    return keyShares;
};

/**
 * Combines multiple public keys into a single public key.
 *
 * @param {bigint[]} publicKeys - An array of public keys to combine.
 * @param {bigint} prime - The prime modulus used in the ElGamal system.
 * @returns {bigint} The combined public key.
 */
export const combinePublicKeys = (
    publicKeys: bigint[],
    prime: bigint,
): bigint => publicKeys.reduce((acc, current) => (acc * current) % prime, 1n);

/**
 * Performs a partial decryption on a ciphertext using an individual's private key share.
 *
 * @param {EncryptedMessage} encryptedMessage - The encrypted message.
 * @param {bigint} privateKeyShare - The private key share of the decrypting party.
 * @param {bigint} prime - The prime modulus used in the ElGamal system.
 * @returns {bigint} The result of the partial decryption.
 */
export const partialDecrypt = (
    encryptedMessage: EncryptedMessage,
    privateKeyShare: bigint,
    prime: bigint,
): bigint => {
    return modPow(encryptedMessage.c1, privateKeyShare, prime);
};

/**
 * Combines partial decryptions from multiple parties into a single decryption factor.
 *
 * @param {bigint[]} partialDecryptions - An array of partial decryption results.
 * @param {bigint} prime - The prime modulus used in the ElGamal system.
 * @returns {bigint} The combined decryption factor.
 */
export const combinePartialDecryptions = (
    partialDecryptions: bigint[],
    prime: bigint,
): bigint => {
    let result = 1n;
    for (const partialDecryption of partialDecryptions) {
        result = (result * partialDecryption) % prime;
    }
    return result;
};

/**
 * Decrypts an encrypted message using the combined partial decryptions in a threshold ElGamal scheme.
 *
 * @param {{ c1: bigint; c2: bigint }} encryptedMessage - The encrypted message components.
 * @param {bigint} combinedPartialDecryptions - The combined partial decryptions from all parties.
 * @param {bigint} prime - The prime modulus used in the ElGamal system.
 * @returns {number} The decrypted message, assuming it was small enough to be directly encrypted.
 */
export const thresholdDecrypt = (
    encryptedMessage: { c1: bigint; c2: bigint },
    combinedPartialDecryptions: bigint,
    prime: bigint,
): number => {
    const combinedDecryptionInverse = modInverse(
        combinedPartialDecryptions,
        prime,
    );
    const plaintext: bigint =
        (encryptedMessage.c2 * combinedDecryptionInverse) % prime;
    return Number(plaintext);
};
