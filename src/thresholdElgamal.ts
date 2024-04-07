import { GROUPS } from './constants';
import type { KeyPair } from './types';
import { getRandomBigInteger, modPow, modInverse } from './utils';

/**
 * Generates an individual ElGamal key pair for a given prime bit length.
 *
 * @param {2048 | 3072 | 4096} primeBits - The bit length of the prime modulus (2048, 3072, or 4096).
 * @returns {KeyPair} The generated key pair including both private and public keys.
 */
export const generateIndividualKeyPair = (
    primeBits: 2048 | 3072 | 4096 = 2048,
): KeyPair => {
    let group;
    switch (primeBits) {
        case 2048:
            group = GROUPS.ffdhe2048;
            break;
        case 3072:
            group = GROUPS.ffdhe3072;
            break;
        case 4096:
            group = GROUPS.ffdhe4096;
            break;
        default:
            throw new Error('Unsupported bit length');
    }

    const prime = group.prime;
    const generator = group.generator;

    const privateKey: bigint = getRandomBigInteger(2n, prime - 1n);
    const publicKey: bigint = modPow(generator, privateKey, prime);

    return { privateKey, publicKey };
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
 * Performs a partial decryption on a ciphertext using an individual's private key.
 *
 * @param {bigint} c1 - The first component of the ciphertext.
 * @param {bigint} privateKey - The private key of the decrypting party.
 * @param {bigint} prime - The prime modulus used in the ElGamal system.
 * @returns {bigint} The result of the partial decryption.
 */
export const partialDecrypt = (
    c1: bigint,
    privateKey: bigint,
    prime: bigint,
): bigint => modPow(c1, privateKey, prime);

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
): bigint =>
    partialDecryptions.reduce((acc, current) => (acc * current) % prime, 1n);

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
