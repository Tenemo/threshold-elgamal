import { GROUPS } from './constants';
import type { EncryptedMessage, Parameters } from './types';
import { getRandomBigInteger, modPow, modInverse } from './utils';

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
    let prime: bigint;
    let generator: bigint;

    switch (primeBits) {
        case 2048:
            prime = BigInt(GROUPS.ffdhe2048.prime);
            generator = BigInt(GROUPS.ffdhe2048.generator);
            break;
        case 3072:
            prime = BigInt(GROUPS.ffdhe3072.prime);
            generator = BigInt(GROUPS.ffdhe3072.generator);
            break;
        case 4096:
            prime = BigInt(GROUPS.ffdhe4096.prime);
            generator = BigInt(GROUPS.ffdhe4096.generator);
            break;
        default:
            throw new Error('Unsupported bit length');
    }

    const privateKey = getRandomBigInteger(2n, prime - 1n);
    const publicKey = modPow(generator, privateKey, prime);

    return { prime, generator, publicKey, privateKey };
};
/**
 * Encrypts a message using ElGamal encryption.
 *
 * @param {number} message - The message to be encrypted.
 * @param {bigint} prime - The prime number used in the encryption system.
 * @param {bigint} generator - The generator used in the encryption system.
 * @param {bigint} publicKey - The public key used for encryption.
 * @returns {EncryptedMessage} The encrypted message, consisting of two BigIntegers (c1 and c2).
 */
export const encrypt = (
    message: number,
    prime: bigint,
    generator: bigint,
    publicKey: bigint,
): EncryptedMessage => {
    const randomNumber = getRandomBigInteger(1n, prime - 1n);

    const c1 = modPow(generator, randomNumber, prime);
    const messageBigInt = BigInt(message);
    const c2 = (modPow(publicKey, randomNumber, prime) * messageBigInt) % prime;

    return { c1, c2 };
};

/**
 * Decrypts an ElGamal encrypted message.
 *
 * @param {EncryptedMessage} message - The encrypted message to decrypt.
 * @param {bigint} prime - The prime number used in the encryption system.
 * @param {bigint} privateKey - The private key used for decryption.
 * @returns {number} The decrypted message as an integer.
 */
export const decrypt = (
    encryptedMessage: EncryptedMessage,
    prime: bigint,
    privateKey: bigint,
): number => {
    const ax: bigint = modPow(encryptedMessage.c1, privateKey, prime);
    const plaintext: bigint =
        (modInverse(ax, prime) * encryptedMessage.c2) % prime;
    return Number(plaintext);
};
