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

describe('Threshold ElGamal Encryption', () => {
    it('allows for secure threshold encryption and decryption', () => {
        // Simulate key generation for 3 parties
        const keyPairs = [1, 2, 3].map(() => generateIndividualKeyPair(2048));
        const publicKeys = keyPairs.map((kp) => kp.publicKey);

        // Combine public keys to create a single public key for encryption
        const prime = GROUPS.ffdhe2048.prime;
        const generator = GROUPS.ffdhe2048.generator;
        const combinedPublicKey = combinePublicKeys(publicKeys, prime);

        const message = 42;
        // Encrypt the message using the combined public key
        const encryptedMessage = encrypt(
            message,
            prime,
            generator,
            combinedPublicKey,
        );

        // Each party partially decrypts the ciphertext
        const partialDecryptions = keyPairs.map((keyPair) =>
            partialDecrypt(encryptedMessage.c1, keyPair.privateKey, prime),
        );

        // Combine partial decryptions to decrypt the message
        const combinedPartialDecryptions = combinePartialDecryptions(
            partialDecryptions,
            prime,
        );

        // Use the combined partial decryptions to fully decrypt the message
        const decryptedMessage = thresholdDecrypt(
            encryptedMessage,
            combinedPartialDecryptions,
            prime,
        );

        // Verify that the decrypted message matches the original
        expect(decryptedMessage).toBe(message);
    });
});
