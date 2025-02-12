import { describe, it, expect } from 'vitest';

import { encrypt } from './elgamal';
import {
    combinePublicKeys,
    createDecryptionShare,
    generateKeys,
    thresholdDecrypt,
    combineDecryptionShares,
} from './thresholdElgamal';
import {
    homomorphicMultiplicationTest,
    testSecureEncryptionAndDecryption,
    votingTest,
} from './utils/testUtils';
import { multiplyEncryptedValues } from './utils/utils';

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
            // it('(t < n) with 3 participants and a threshold of 2', () => {
            //     testSecureEncryptionAndDecryption(3, 2, 123);
            // });
            // it('(t < n) with 5 participants and a threshold of 3', () => {
            //     testSecureEncryptionAndDecryption(5, 3, 255);
            // });
            // it('(t < n) with 7 participants and a threshold of 4', () => {
            //     testSecureEncryptionAndDecryption(7, 4, 789);
            // });
        });
        it('works for the 3,3 step-by-step README example', () => {
            const threshold = 3; // A scenario for 3 participants with a threshold of 3

            // Each participant generates their public key share and private key individually
            const participant1Keys = generateKeys(1, threshold);
            const participant2Keys = generateKeys(2, threshold);
            const participant3Keys = generateKeys(3, threshold);

            // Combine the public keys to form a single public key
            const commonPublicKey = combinePublicKeys([
                participant1Keys.publicKey,
                participant2Keys.publicKey,
                participant3Keys.publicKey,
            ]);

            // Encrypt a message using the combined public key
            const secret = 42;
            const encryptedMessage = encrypt(secret, commonPublicKey);

            // Decryption shares
            const decryptionShares = [
                createDecryptionShare(
                    encryptedMessage,
                    participant1Keys.privateKey,
                ),
                createDecryptionShare(
                    encryptedMessage,
                    participant2Keys.privateKey,
                ),
                createDecryptionShare(
                    encryptedMessage,
                    participant3Keys.privateKey,
                ),
            ];
            // Combining the decryption shares into one, used to decrypt the message
            const combinedDecryptionShares =
                combineDecryptionShares(decryptionShares);

            // Decrypting the message using the combined decryption shares
            const thresholdDecryptedMessage = thresholdDecrypt(
                encryptedMessage,
                combinedDecryptionShares,
            );
            console.log(thresholdDecryptedMessage); // 42
            expect(thresholdDecryptedMessage).toBe(secret);
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
            // it('(t < n) with 3 participants and a threshold of 2', () => {
            //     homomorphicMultiplicationTest(3, 2, [2, 3, 4]);
            // });
            // it('(t < n) with 5 participants and a threshold of 3', () => {
            //     homomorphicMultiplicationTest(5, 3, [1, 2, 3, 4, 5]);
            // });
            // it('(t < n) with 10 participants and a threshold of 5', () => {
            //     homomorphicMultiplicationTest(
            //         10,
            //         5,
            //         [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            //     );
            // });
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
            // it('(t < n) with 3 participants, threshold of 2 and 2 candidates', () => {
            //     votingTest(3, 2, 2);
            // });
            // it('(t < n) with 7 participants, threshold of 5 and 3 candidates', () => {
            //     votingTest(7, 5, 3);
            // });
        });
        it('works for the 3, 3, 2 step-by-step README example', () => {
            const threshold = 3; // A scenario for 3 participants with a threshold of 3

            // Each participant generates their public key share and private key individually
            const participant1Keys = generateKeys(1, threshold);
            const participant2Keys = generateKeys(2, threshold);
            const participant3Keys = generateKeys(3, threshold);

            // Combine the public keys to form a single public key
            const commonPublicKey = combinePublicKeys([
                participant1Keys.publicKey,
                participant2Keys.publicKey,
                participant3Keys.publicKey,
            ]);

            // Participants cast their encrypted votes for two options
            const voteOption1 = [6, 7, 1]; // Votes for option 1 by participants 1, 2, and 3
            const voteOption2 = [10, 7, 4]; // Votes for option 2 by participants 1, 2, and 3

            // Encrypt votes for both options
            const encryptedVotesOption1 = voteOption1.map((vote) =>
                encrypt(vote, commonPublicKey),
            );
            const encryptedVotesOption2 = voteOption2.map((vote) =>
                encrypt(vote, commonPublicKey),
            );

            // Multiply encrypted votes together to aggregate
            const aggregatedEncryptedVoteOption1 = encryptedVotesOption1.reduce(
                (talliedVotes, encryptedVote) =>
                    multiplyEncryptedValues(talliedVotes, encryptedVote),
                { c1: 1n, c2: 1n },
            );
            const aggregatedEncryptedVoteOption2 = encryptedVotesOption2.reduce(
                (talliedVotes, encryptedVote) =>
                    multiplyEncryptedValues(talliedVotes, encryptedVote),
                { c1: 1n, c2: 1n },
            );

            // Each participant creates a decryption share for both options.
            // Notice that the shares are created for the aggregated, multiplied tally specifically,
            // not the individual votes. This means that they can be used ONLY for decrypting the aggregated votes.
            const decryptionSharesOption1 = [
                createDecryptionShare(
                    aggregatedEncryptedVoteOption1,
                    // The order of the shares does not matter during decryption.
                    participant3Keys.privateKey,
                ),
                createDecryptionShare(
                    aggregatedEncryptedVoteOption1,
                    participant1Keys.privateKey,
                ),
                createDecryptionShare(
                    aggregatedEncryptedVoteOption1,
                    participant2Keys.privateKey,
                ),
            ];
            const decryptionSharesOption2 = [
                createDecryptionShare(
                    aggregatedEncryptedVoteOption2,
                    participant2Keys.privateKey,
                ),
                createDecryptionShare(
                    aggregatedEncryptedVoteOption2,
                    participant1Keys.privateKey,
                ),
                createDecryptionShare(
                    aggregatedEncryptedVoteOption2,
                    participant3Keys.privateKey,
                ),
            ];

            // Combine decryption shares and decrypt the aggregated votes for both options.
            // Notice that the private keys of the participants never leave their possession.
            // Only the decryption shares are shared with other participants.
            const combinedDecryptionSharesOption1 = combineDecryptionShares(
                decryptionSharesOption1,
            );
            const combinedDecryptionSharesOption2 = combineDecryptionShares(
                decryptionSharesOption2,
            );

            const finalTallyOption1 = thresholdDecrypt(
                aggregatedEncryptedVoteOption1,
                combinedDecryptionSharesOption1,
            );
            const finalTallyOption2 = thresholdDecrypt(
                aggregatedEncryptedVoteOption2,
                combinedDecryptionSharesOption2,
            );

            console.log(
                `Final tally for Option 1: ${finalTallyOption1}, Option 2: ${finalTallyOption2}`,
            ); // 42, 280
            expect(finalTallyOption1).toBe(42);
            expect(finalTallyOption2).toBe(280);
        });
    });
});
