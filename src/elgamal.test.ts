import { describe, it, expect } from 'vitest';

import { GROUPS } from './constants';
import { generateParameters, encrypt, decrypt } from './elgamal';
import { multiplyEncryptedValues } from './utils/utils';

describe('ElGamal: ', () => {
    Object.entries(GROUPS).forEach(([groupName, groupInfo]) => {
        const { primeBits, prime, generator } = groupInfo;
        const { publicKey, privateKey } = generateParameters(primeBits);

        it(`${primeBits}-bit encryption and decryption using ${groupName}`, () => {
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

        it('homomorphic multiplication', () => {
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
