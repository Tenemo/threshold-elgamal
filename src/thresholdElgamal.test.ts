import { expect, describe, it } from 'vitest';

import { GROUPS } from './constants';
import { encrypt } from './elgamal';
import {
    generateIndividualKeyPair,
    combinePublicKeys,
    partialDecrypt,
    combinePartialDecryptions,
    thresholdDecrypt,
} from './thresholdElgamal';
import type { KeyPair } from './types';
import { multiplyEncryptedValues } from './utils';

const thresholdSetup = (
    partiesCount: number,
    primeBits: 2048 | 3072 | 4096 = 2048,
): {
    keyPairs: KeyPair[];
    combinedPublicKey: bigint;
    prime: bigint;
    generator: bigint;
} => {
    const keyPairs = Array.from({ length: partiesCount }, () =>
        generateIndividualKeyPair(primeBits),
    );
    const publicKeys = keyPairs.map((kp) => kp.publicKey);
    const prime = GROUPS[`ffdhe${primeBits}`].prime;
    const generator = GROUPS[`ffdhe${primeBits}`].generator;
    const combinedPublicKey = combinePublicKeys(publicKeys, prime);

    return { keyPairs, combinedPublicKey, prime, generator };
};

describe('Threshold ElGamal Encryption', () => {
    it('allows for secure threshold encryption and decryption', () => {
        const { keyPairs, combinedPublicKey, prime, generator } =
            thresholdSetup(3);
        const message = 42;
        const encryptedMessage = encrypt(
            message,
            prime,
            generator,
            combinedPublicKey,
        );
        const partialDecryptions = keyPairs.map((keyPair) =>
            partialDecrypt(encryptedMessage.c1, keyPair.privateKey, prime),
        );
        const combinedPartialDecryptions = combinePartialDecryptions(
            partialDecryptions,
            prime,
        );
        const decryptedMessage = thresholdDecrypt(
            encryptedMessage,
            combinedPartialDecryptions,
            prime,
        );
        expect(decryptedMessage).toBe(message);
    });

    it('supports homomorphic multiplication of encrypted messages', () => {
        const { keyPairs, combinedPublicKey, prime, generator } =
            thresholdSetup(2);
        const message1 = 3;
        const encryptedMessage1 = encrypt(
            message1,
            prime,
            generator,
            combinedPublicKey,
        );
        const message2 = 5;
        const encryptedMessage2 = encrypt(
            message2,
            prime,
            generator,
            combinedPublicKey,
        );
        const encryptedProduct = multiplyEncryptedValues(
            encryptedMessage1,
            encryptedMessage2,
            prime,
        );
        const partialDecryptions = keyPairs.map((keyPair) =>
            partialDecrypt(encryptedProduct.c1, keyPair.privateKey, prime),
        );
        const combinedPartialDecryptions = combinePartialDecryptions(
            partialDecryptions,
            prime,
        );
        const decryptedProduct = thresholdDecrypt(
            encryptedProduct,
            combinedPartialDecryptions,
            prime,
        );
        expect(decryptedProduct).toBe(message1 * message2);
    });
});
