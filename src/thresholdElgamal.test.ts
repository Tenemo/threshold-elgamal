import crypto from 'crypto';

import { modPow, modInv } from 'bigint-mod-arith';
import { expect, describe, it } from 'vitest';

import { encrypt } from './elgamal';
import {
    thresholdSetup,
    homomorphicMultiplicationTest,
    getRandomScore,
    testSecureEncryptionAndDecryption,
} from './testUtils';
import {
    createDecryptionShare,
    combineDecryptionShares,
    thresholdDecrypt,
    getGroup,
    generateKeyShares,
} from './thresholdElgamal';
import { multiplyEncryptedValues, getRandomBigIntegerInRange } from './utils';

describe('Threshold ElGamal', () => {
    it('correct encryption and decryption with 3 participantsCount and a threshold of 2', () => {
        const participantsCount = 3;
        const threshold = 2;
        const secret = 42;
        console.log(`Secret: ${secret}`);

        const group = getGroup(2048); // ffdhe2048 group
        const prime = group.prime;
        const generator = group.generator;
        // ...
    });

    describe('allows for secure encryption and decryption', () => {
        it('with 2 participants and a threshold of 2', () => {
            testSecureEncryptionAndDecryption(2, 2, 42);
        });
        // it('with 3 participants and a threshold of 2', () => {
        //     testSecureEncryptionAndDecryption(3, 2, 123);
        // });
        // it('with 5 participants and a threshold of 3', () => {
        //     testSecureEncryptionAndDecryption(5, 3, 255);
        // });
        // it('with 7 participants and a threshold of 4', () => {
        //     testSecureEncryptionAndDecryption(7, 4, 789);
        // });
    });

    describe('supports homomorphic multiplication of encrypted messages', () => {
        it('with 2 participants and a threshold of 2', () => {
            homomorphicMultiplicationTest(2, 2, [3, 5]);
        });
        // it('with 10 participants and a threshold of 10', () => {
        //     homomorphicMultiplicationTest(
        //         10,
        //         10,
        //         [13, 24, 35, 46, 5, 6, 7, 8, 9, 10],
        //     );
        // });
        // it('with 3 participants and a threshold of 2', () => {
        //     homomorphicMultiplicationTest(3, 2, [2, 3, 4]);
        // });
        // it('with 5 participants and a threshold of 3', () => {
        //     homomorphicMultiplicationTest(5, 3, [1, 2, 3, 4, 5]);
        // });
        // it('with 10 participants and a threshold of 5', () => {
        //     homomorphicMultiplicationTest(
        //         10,
        //         5,
        //         [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        //     );
        // });
    });

    // it('correctly calculates and verifies products from encrypted votes', () => {
    //     const participantsCount = 3;
    //     const threshold = 2;
    //     const candidates = 3;
    //     const { keyShares, combinedPublicKey, prime, generator } =
    //         thresholdSetup(participantsCount, threshold);
    //     const votesMatrix = Array.from({ length: participantsCount }, () =>
    //         Array.from({ length: candidates }, () => getRandomScore(1, 10)),
    //     );
    //     const expectedProducts = Array.from(
    //         { length: candidates },
    //         (_, candidateIndex) =>
    //             votesMatrix.reduce(
    //                 (product, votes) => product * votes[candidateIndex],
    //                 1,
    //             ),
    //     );
    //     const encryptedVotesMatrix = votesMatrix.map((votes) =>
    //         votes.map((vote) =>
    //             encrypt(vote, prime, generator, combinedPublicKey),
    //         ),
    //     );
    //     const encryptedProducts = Array.from(
    //         { length: candidates },
    //         (_, candidateIndex) =>
    //             encryptedVotesMatrix.reduce(
    //                 (product, encryptedVotes) =>
    //                     multiplyEncryptedValues(
    //                         product,
    //                         encryptedVotes[candidateIndex],
    //                         prime,
    //                     ),
    //                 { c1: 1n, c2: 1n },
    //             ),
    //     );
    //     const partialDecryptionsMatrix = encryptedProducts.map((product) =>
    //         keyShares
    //             .slice(0, threshold)
    //             .map((keyShare) =>
    //                 createDecryptionShare(
    //                     product,
    //                     keyShare.partyPrivateKey,
    //                     prime,
    //                 ),
    //             ),
    //     );
    //     const decryptedProducts = partialDecryptionsMatrix.map(
    //         (decryptionShares) => {
    //             const combinedDecryptionShares = combineDecryptionShares(
    //                 decryptionShares,
    //                 prime,
    //             );
    //             const encryptedProduct =
    //                 encryptedProducts[
    //                     partialDecryptionsMatrix.indexOf(decryptionShares)
    //                 ];
    //             return thresholdDecrypt(
    //                 encryptedProduct,
    //                 combinedDecryptionShares,
    //                 prime,
    //             );
    //         },
    //     );
    //     expect(decryptedProducts).toEqual(expectedProducts);
    // });
});
