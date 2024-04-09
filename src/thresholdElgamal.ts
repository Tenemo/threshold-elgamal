import { modPow, modInv } from 'bigint-mod-arith';

import type { EncryptedMessage, PartyKeyPair } from './types';
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
 * @returns {PartyKeyPair} The key share containing a private and public key share for the participant.
 */
export const generateSingleKeyShare = (
    index: number,
    threshold: number,
    primeBits: 2048 | 3072 | 4096 = 2048,
): PartyKeyPair => {
    const group = getGroup(primeBits);
    const prime = group.prime;
    const generator = group.generator;
    const polynomial = generatePolynomial(threshold, prime);
    let partyPrivateKey = evaluatePolynomial(polynomial, index, prime);
    // Ensure non-zero private key, adjusting index if necessary
    while (partyPrivateKey === 0n) {
        partyPrivateKey = evaluatePolynomial(polynomial, index + 1, prime);
    }
    const partyPublicKey = modPow(generator, partyPrivateKey, prime);

    return { partyPrivateKey, partyPublicKey };
};

/**
 * Generates key shares for a threshold ElGamal cryptosystem.
 *
 * @param {number} n - The total number of key shares.
 * @param {number} threshold - The minimum number of key shares required for decryption.
 * @param {2048 | 3072 | 4096} primeBits - The bit length of the prime modulus (default: 2048).
 * @returns {PartyKeyPair[]} An array of key shares, each containing a private and public key share.
 */
export const generateKeyShares = (
    n: number,
    threshold: number,
    primeBits: 2048 | 3072 | 4096 = 2048,
): PartyKeyPair[] => {
    const keyShares = [];
    for (let i = 1; i <= n; i++) {
        const keyShare = generateSingleKeyShare(i, threshold, primeBits);
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
    prime: bigint,
): bigint => publicKeys.reduce((acc, current) => (acc * current) % prime, 1n);

/**
 * Performs a partial decryption on a ciphertext using an individual's private key share.
 *
 * @param {EncryptedMessage} encryptedMessage - The encrypted secret.
 * @param {bigint} partyPrivateKey - The private key share of the decrypting party.
 * @param {bigint} prime - The prime modulus used in the ElGamal system.
 * @returns {bigint} The result of the partial decryption.
 */
export const createDecryptionShare = (
    encryptedMessage: EncryptedMessage,
    partyPrivateKey: bigint,
    prime: bigint,
): bigint => modPow(encryptedMessage.c1, partyPrivateKey, prime);

/**
 * Combines partial decryptions from multiple parties into a single decryption factor.
 *
 * @param {bigint[]} decryptionShares - An array of partial decryption results.
 * @param {bigint} prime - The prime modulus used in the ElGamal system.
 * @returns {bigint} The combined decryption factor.
 */
export const combineDecryptionShares = (
    decryptionShares: bigint[],
    prime: bigint,
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
 * @param {bigint} prime - The prime modulus used in the ElGamal system.
 * @returns {number} The decrypted secret, assuming it was small enough to be directly encrypted.
 */
export const thresholdDecrypt = (
    encryptedMessage: { c1: bigint; c2: bigint },
    combinedDecryptionShares: bigint,
    prime: bigint,
): number => {
    const combinedDecryptionInverse = modInv(combinedDecryptionShares, prime);
    const plaintext: bigint =
        (encryptedMessage.c2 * combinedDecryptionInverse) % prime;
    return Number(plaintext);
};
