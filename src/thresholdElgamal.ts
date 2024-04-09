import { modPow, modInv } from 'bigint-mod-arith';

import type { EncryptedMessage } from './types';
import { generatePolynomial, getGroup } from './utils/utils';

/**
 * Evaluates a polynomial at a given point using modular arithmetic.
 *
 * @param {bigint[]} polynomial - The coefficients of the polynomial.
 * @param {number} x - The point at which to evaluate the polynomial.
 * @param {bigint} prime - The prime modulus.
 * @returns {bigint} The result of the polynomial evaluation.
 */
export const evaluatePolynomial = (
    polynomial: bigint[],
    x: number,
    prime: bigint,
): bigint => {
    let result = 0n;
    for (let i = 0; i < polynomial.length; i++) {
        result = (result + polynomial[i] * BigInt(x) ** BigInt(i)) % prime;
    }
    return result;
};

/**
 * Generates a single key share for a participant in a threshold ElGamal cryptosystem.
 *
 * @param {number} index - The unique index of the participant (starting from 1).
 * @param {number} threshold - The minimum number of key shares required for decryption.
 * @param {2048 | 3072 | 4096} primeBits - The bit length of the prime modulus (default: 2048).
 * @returns { privateKey: bigint; publicKey: bigint} The key share containing a private and public key share for the participant.
 */
export const generateKeys = (
    index: number,
    threshold: number,
    primeBits: 2048 | 3072 | 4096 = 2048,
): { privateKey: bigint; publicKey: bigint } => {
    const group = getGroup(primeBits);
    const prime = group.prime;
    const generator = group.generator;
    const polynomial = generatePolynomial(threshold, prime);
    let privateKey = evaluatePolynomial(polynomial, index, prime);
    // Ensure non-zero private key, adjusting index if necessary
    while (privateKey === 0n) {
        privateKey = evaluatePolynomial(polynomial, index + 1, prime);
    }
    const publicKey = modPow(generator, privateKey, prime);

    return { privateKey, publicKey };
};

/**
 * Generates key shares for a threshold ElGamal cryptosystem.
 *
 * @param {number} n - The total number of key shares.
 * @param {number} threshold - The minimum number of key shares required for decryption.
 * @param {2048 | 3072 | 4096} primeBits - The bit length of the prime modulus (default: 2048).
 * @returns {{ privateKey: bigint; publicKey: bigint }[]} An array of key shares, each containing a private and public key share.
 */
export const generateKeyShares = (
    n: number,
    threshold: number,
    primeBits: 2048 | 3072 | 4096 = 2048,
): { privateKey: bigint; publicKey: bigint }[] => {
    const keyShares = [];
    for (let i = 1; i <= n; i++) {
        const keyShare = generateKeys(i, threshold, primeBits);
        keyShares.push(keyShare);
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
    prime: bigint = getGroup().prime,
): bigint =>
    publicKeys.reduce(
        (combinedPublicKey, current) => (combinedPublicKey * current) % prime,
        1n,
    );

/**
 * Performs a partial decryption on a ciphertext using an individual's private key share.
 *
 * @param {EncryptedMessage} encryptedMessage - The encrypted secret.
 * @param {bigint} privateKey - The private key share of the decrypting party.
 * @param {bigint} prime - The prime modulus used in the ElGamal system. Defaults to the 2048-bit group prime.
 * @returns {bigint} The result of the partial decryption.
 */
export const createDecryptionShare = (
    encryptedMessage: EncryptedMessage,
    privateKey: bigint,
    prime: bigint = getGroup().prime,
): bigint => modPow(encryptedMessage.c1, privateKey, prime);

/**
 * Combines partial decryptions from multiple parties into a single decryption factor.
 *
 * @param {bigint[]} decryptionShares - An array of partial decryption results.
 * @param {bigint} prime - The prime modulus used in the ElGamal system. Defaults to the 2048-bit group prime.
 * @returns {bigint} The combined decryption factor.
 */
export const combineDecryptionShares = (
    decryptionShares: bigint[],
    prime: bigint = getGroup().prime,
): bigint => {
    let result = 1n;
    for (const partialDecryption of decryptionShares) {
        result = (result * partialDecryption) % prime;
    }
    return result;
};

/**
 * Decrypts an encrypted secret using the combined partial decryptions in a threshold ElGamal scheme.
 *
 * @param {{ c1: bigint; c2: bigint }} encryptedMessage - The encrypted secret components.
 * @param {bigint} combinedDecryptionShares - The combined partial decryptions from all parties.
 * @param {bigint} prime - The prime modulus used in the ElGamal system. Defaults to the 2048-bit group prime.
 * @returns {number} The decrypted secret, assuming it was small enough to be directly encrypted.
 */
export const thresholdDecrypt = (
    encryptedMessage: { c1: bigint; c2: bigint },
    combinedDecryptionShares: bigint,
    prime: bigint = getGroup().prime,
): number => {
    const combinedDecryptionInverse = modInv(combinedDecryptionShares, prime);
    const plaintext: bigint =
        (encryptedMessage.c2 * combinedDecryptionInverse) % prime;
    return Number(plaintext);
};
