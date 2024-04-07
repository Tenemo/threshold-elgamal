import { expect, describe, it } from 'vitest';

import { encrypt } from './elgamal';
import {
    thresholdSetup,
    homomorphicMultiplicationTest,
    getRandomScore,
} from './testUtils';
import {
    partialDecrypt,
    combinePartialDecryptions,
    thresholdDecrypt,
} from './thresholdElgamal';
import { multiplyEncryptedValues } from './utils';

describe('Threshold ElGamal', () => {
    it('allows for secure encryption and decryption', () => {
        const threshold = 2;
        const { keyShares, combinedPublicKey, prime, generator } =
            thresholdSetup(3, threshold);
        const message = 42;
        const encryptedMessage = encrypt(
            message,
            prime,
            generator,
            combinedPublicKey,
        );
        const partialDecryptions = keyShares
            .slice(0, threshold)
            .map((keyShare) =>
                partialDecrypt(
                    encryptedMessage,
                    keyShare.privateKeyShare,
                    prime,
                ),
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
        homomorphicMultiplicationTest(2, 2, [3, 5]);
        homomorphicMultiplicationTest(3, 2, [2, 3, 4]);
        homomorphicMultiplicationTest(5, 3, [1, 2, 3, 4, 5]);
        homomorphicMultiplicationTest(10, 5, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
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
