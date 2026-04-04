import { describe, expect, it } from 'vitest';

import { GROUPS } from '../../src/constants';
import { decrypt, encrypt, generateParameters } from '../../src/elgamal';
import { multiplyEncryptedValues } from '../../src/utils/utils';

describe('elgamal', () => {
    it('works for the readme example', () => {
        const { publicKey, privateKey, prime, generator } =
            generateParameters();
        const secret = 859;
        const encryptedMessage = encrypt(secret, publicKey, prime, generator);
        const decryptedMessage = decrypt(encryptedMessage, prime, privateKey);

        expect(decryptedMessage).toBe(secret);
    });

    describe('handles different groups', () => {
        Object.entries(GROUPS).forEach(([groupName, groupInfo]) => {
            const { primeBits, prime, generator } = groupInfo;

            it(`${primeBits}-bit encryption and decryption using ${groupName}`, () => {
                const { publicKey, privateKey } = generateParameters(primeBits);
                const secret = 42;
                const encryptedMessage = encrypt(
                    secret,
                    publicKey,
                    prime,
                    generator,
                );
                const decryptedMessage = decrypt(
                    encryptedMessage,
                    prime,
                    privateKey,
                );

                expect(decryptedMessage).toBe(secret);
            });

            it(`${primeBits}-bit homomorphic multiplication using ${groupName}`, () => {
                const { publicKey, privateKey } = generateParameters(primeBits);
                const message1 = 12;
                const message2 = 13;
                const expectedProduct = message1 * message2;

                const encryptedMessage1 = encrypt(
                    message1,
                    publicKey,
                    prime,
                    generator,
                );
                const encryptedMessage2 = encrypt(
                    message2,
                    publicKey,
                    prime,
                    generator,
                );
                const encryptedProduct = multiplyEncryptedValues(
                    encryptedMessage1,
                    encryptedMessage2,
                    prime,
                );
                const decryptedMessage = decrypt(
                    encryptedProduct,
                    prime,
                    privateKey,
                );

                expect(decryptedMessage).toBe(expectedProduct);
            });
        });
    });
});
