import { describe, it, expect } from 'vitest';

import { GROUPS } from './constants';
import { generateParameters, encrypt, decrypt } from './elgamal';
import { multiplyEncryptedValues } from './utils/utils';

describe('ElGamal', () => {
    it(`works for the README example`, () => {
        // Generate a public/private key pair
        // If prime and generator aren't specified, they default to the 2048-bit group.
        const { publicKey, privateKey, prime, generator } =
            generateParameters();

        // Encrypt a message using the public key:
        const secret = 859;
        const encryptedMessage = encrypt(secret, publicKey, prime, generator);

        // Decrypt the message using the private key:
        const decryptedMessage = decrypt(encryptedMessage, prime, privateKey);
        // console.log(decryptedMessage); // 859
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
                const m1 = 12;
                const m2 = 13;
                const m1m2 = m1 * m2;

                const e1 = encrypt(m1, publicKey, prime, generator);
                const e2 = encrypt(m2, publicKey, prime, generator);
                const e1e2 = multiplyEncryptedValues(e1, e2, prime);
                const decryptedMessage = decrypt(e1e2, prime, privateKey);

                expect(decryptedMessage).toBe(m1m2);
            });
        });
    });
});
