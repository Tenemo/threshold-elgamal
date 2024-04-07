import { describe, it } from 'vitest';

import {
    homomorphicMultiplicationTest,
    testSecureEncryptionAndDecryption,
    votingTest,
} from './testUtils';

// I already have modPow, modInv and getRandomBigIntegerInRange
describe('Threshold ElGamal', () => {
    describe('in a single secret scheme', () => {
        describe('allows for secure encryption and decryption', () => {
            it('with 2 participants and a threshold of 2', () => {
                testSecureEncryptionAndDecryption(2, 2, 42);
            });
            it('with 20 participants and a threshold of 20', () => {
                testSecureEncryptionAndDecryption(20, 20, 4243);
            });

            // Failing tests
            it('(t < n) with 3 participants and a threshold of 2', () => {
                testSecureEncryptionAndDecryption(3, 2, 123);
            });
            it('(t < n) with 5 participants and a threshold of 3', () => {
                testSecureEncryptionAndDecryption(5, 3, 255);
            });
            it('(t < n) with 7 participants and a threshold of 4', () => {
                testSecureEncryptionAndDecryption(7, 4, 789);
            });
        });
    });
    describe('in a multiple secrets scheme', () => {
        describe('supports homomorphic multiplication of encrypted messages', () => {
            it('with 2 participants and a threshold of 2', () => {
                homomorphicMultiplicationTest(2, 2, [3, 5]);
            });
            it('with 10 participants and a threshold of 10', () => {
                homomorphicMultiplicationTest(
                    10,
                    10,
                    [13, 24, 35, 46, 5, 6, 7, 8, 9, 10],
                );
            });

            // Failing tests
            it('(t < n) with 3 participants and a threshold of 2', () => {
                homomorphicMultiplicationTest(3, 2, [2, 3, 4]);
            });
            it('(t < n) with 5 participants and a threshold of 3', () => {
                homomorphicMultiplicationTest(5, 3, [1, 2, 3, 4, 5]);
            });
            it('(t < n) with 10 participants and a threshold of 5', () => {
                homomorphicMultiplicationTest(
                    10,
                    5,
                    [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
                );
            });
        });
        describe('supports voting', () => {
            it('with 2 participants, threshold of 2 and 2 candidates', () => {
                votingTest(2, 2, 2);
            });
            it('with 5 participants, threshold of 5 and 3 candidates', () => {
                votingTest(5, 5, 3);
            });
            it('with 7 participants, threshold of 7 and 7 candidates', () => {
                votingTest(7, 7, 7);
            });
            it('with 6 participants, threshold of 6 and 8 candidates', () => {
                votingTest(6, 6, 8);
            });

            // Failing tests
            it('(t < n) with 3 participants, threshold of 2 and 2 candidates', () => {
                votingTest(3, 2, 2);
            });
            it('(t < n) with 7 participants, threshold of 5 and 3 candidates', () => {
                votingTest(7, 5, 3);
            });
        });
    });
});
