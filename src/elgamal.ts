import { modPow, modInv } from 'bigint-mod-arith';

import type { EncryptedMessage, Parameters } from './types';
import { getRandomBigIntegerInRange, getGroup } from './utils';

/**
 * Generates the parameters for the ElGamal encryption, including the prime, generator,
 * and key pair (public and private keys).
 *
 * @param {2048 | 3072 | 4096} primeBits - The bit length for the prime number. Supports 2048, 3072, or 4096 bits.
 * @returns {Parameters} The generated parameters including the prime, generator, publicKey, and privateKey.
 */
export const generateParameters = (
    primeBits: 2048 | 3072 | 4096 = 2048,
): Parameters => {
    const { prime, generator } = getGroup(primeBits); // Use getGroup to fetch the prime and generator

    const privateKey = getRandomBigIntegerInRange(2n, prime - 1n);
    const publicKey = modPow(generator, privateKey, prime);

    return { prime, generator, publicKey, privateKey };
};
/**
 * Encrypts a secret using ElGamal encryption.
 *
 * @param {number} secret - The secret to be encrypted.
 * @param {bigint} prime - The prime number used in the encryption system.
 * @param {bigint} generator - The generator used in the encryption system.
 * @param {bigint} publicKey - The public key used for encryption.
 * @returns {EncryptedMessage} The encrypted secret, consisting of two BigIntegers (c1 and c2).
 */
export const encrypt = (
    secret: number,
    prime: bigint,
    generator: bigint,
    publicKey: bigint,
): EncryptedMessage => {
    if (secret >= Number(prime)) {
        throw new Error('Message is too large for direct encryption');
    }
    const randomNumber = getRandomBigIntegerInRange(1n, prime - 1n);

    const c1 = modPow(generator, randomNumber, prime);
    const messageBigInt = BigInt(secret);
    const c2 = (modPow(publicKey, randomNumber, prime) * messageBigInt) % prime;

    return { c1, c2 };
};

/**
 * Decrypts an ElGamal encrypted secret.
 *
 * @param {EncryptedMessage} secret - The encrypted secret to decrypt.
 * @param {bigint} prime - The prime number used in the encryption system.
 * @param {bigint} privateKey - The private key used for decryption.
 * @returns {number} The decrypted secret as an integer.
 */
export const decrypt = (
    encryptedMessage: EncryptedMessage,
    prime: bigint,
    privateKey: bigint,
): number => {
    const ax: bigint = modPow(encryptedMessage.c1, privateKey, prime);
    const plaintext: bigint = (modInv(ax, prime) * encryptedMessage.c2) % prime;
    return Number(plaintext);
};
