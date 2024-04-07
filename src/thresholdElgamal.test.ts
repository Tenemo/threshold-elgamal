import { expect, describe, it } from 'vitest';

import { encrypt } from './elgamal';
import {
    thresholdSetup,
    homomorphicMultiplicationTest,
    getRandomScore,
    testSecureEncryptionAndDecryption,
} from './testUtils';
import {
    partialDecrypt,
    combinePartialDecryptions,
    thresholdDecrypt,
} from './thresholdElgamal';
import { multiplyEncryptedValues } from './utils';

describe('Threshold ElGamal', () => {
    describe('allows for secure encryption and decryption', () => {
        it('with 2 participants and a threshold of 2', () => {
            testSecureEncryptionAndDecryption(2, 2, 42);
        });
        it('with 3 participants and a threshold of 2', () => {
            testSecureEncryptionAndDecryption(3, 2, 123);
        });
        it('with 5 participants and a threshold of 3', () => {
            testSecureEncryptionAndDecryption(5, 3, 255);
        });
        it('with 7 participants and a threshold of 4', () => {
            testSecureEncryptionAndDecryption(7, 4, 789);
        });
    });

    describe('supports homomorphic multiplication of encrypted messages', () => {
        it('with 2 participants and a threshold of 2', () => {
            homomorphicMultiplicationTest(2, 2, [3, 5]);
        });
        it('with 3 participants and a threshold of 2', () => {
            homomorphicMultiplicationTest(3, 2, [2, 3, 4]);
        });
        it('with 5 participants and a threshold of 3', () => {
            homomorphicMultiplicationTest(5, 3, [1, 2, 3, 4, 5]);
        });
        it('with 10 participants and a threshold of 5', () => {
            homomorphicMultiplicationTest(
                10,
                5,
                [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            );
        });
    });

    it('correctly calculates and verifies products from encrypted votes', () => {
        const participants = 3;
        const threshold = 2;
        const candidates = 3;
        const { keyShares, combinedPublicKey, prime, generator } =
            thresholdSetup(participants, threshold);
        const votesMatrix = Array.from({ length: participants }, () =>
            Array.from({ length: candidates }, () => getRandomScore(1, 10)),
        );
        const expectedProducts = Array.from(
            { length: candidates },
            (_, candidateIndex) =>
                votesMatrix.reduce(
                    (product, votes) => product * votes[candidateIndex],
                    1,
                ),
        );
        const encryptedVotesMatrix = votesMatrix.map((votes) =>
            votes.map((vote) =>
                encrypt(vote, prime, generator, combinedPublicKey),
            ),
        );
        const encryptedProducts = Array.from(
            { length: candidates },
            (_, candidateIndex) =>
                encryptedVotesMatrix.reduce(
                    (product, encryptedVotes) =>
                        multiplyEncryptedValues(
                            product,
                            encryptedVotes[candidateIndex],
                            prime,
                        ),
                    { c1: 1n, c2: 1n },
                ),
        );
        const partialDecryptionsMatrix = encryptedProducts.map((product) =>
            keyShares
                .slice(0, threshold)
                .map((keyShare) =>
                    partialDecrypt(product, keyShare.privateKeyShare, prime),
                ),
        );
        const decryptedProducts = partialDecryptionsMatrix.map(
            (partialDecryptions) => {
                const combinedPartialDecryptions = combinePartialDecryptions(
                    partialDecryptions,
                    prime,
                );
                const encryptedProduct =
                    encryptedProducts[
                        partialDecryptionsMatrix.indexOf(partialDecryptions)
                    ];
                return thresholdDecrypt(
                    encryptedProduct,
                    combinedPartialDecryptions,
                    prime,
                );
            },
        );
        expect(decryptedProducts).toEqual(expectedProducts);
    });
});
