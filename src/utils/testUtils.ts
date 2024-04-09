import { expect } from 'vitest';

import { encrypt } from '../elgamal';
import {
    generateKeyShares,
    combinePublicKeys,
    createDecryptionShare,
    combineDecryptionShares,
    thresholdDecrypt,
} from '../thresholdElgamal';

import { multiplyEncryptedValues, getGroup } from './utils';

export const getRandomScore = (min = 1, max = 10): number =>
    Math.floor(Math.random() * (max - min + 1)) + min;

export const thresholdSetup = (
    partiesCount: number,
    threshold: number,
    primeBits: 2048 | 3072 | 4096 = 2048,
): {
    keyShares: { privateKey: bigint; publicKey: bigint }[];
    commonPublicKey: bigint;
    prime: bigint;
    generator: bigint;
} => {
    const { prime, generator } = getGroup(primeBits);
    const keyShares = generateKeyShares(partiesCount, threshold, primeBits);
    const publicKeys = keyShares.map((ks) => ks.publicKey);
    const commonPublicKey = combinePublicKeys(publicKeys, prime);

    return { keyShares, commonPublicKey, prime, generator };
};

export const testSecureEncryptionAndDecryption = (
    participantsCount: number,
    threshold: number,
    secret: number,
): void => {
    const { keyShares, commonPublicKey, prime, generator } = thresholdSetup(
        participantsCount,
        threshold,
    );
    const encryptedMessage = encrypt(secret, prime, generator, commonPublicKey);
    const selectedDecryptionShares = keyShares
        .sort(() => Math.random() - 0.5)
        .slice(0, threshold)
        .map(({ privateKey }) =>
            createDecryptionShare(encryptedMessage, privateKey, prime),
        );
    const combinedDecryptionShares = combineDecryptionShares(
        selectedDecryptionShares,
        prime,
    );
    const decryptedMessage = thresholdDecrypt(
        encryptedMessage,
        combinedDecryptionShares,
        prime,
    );
    expect(decryptedMessage).toBe(secret);
};

export const homomorphicMultiplicationTest = (
    participantsCount: number,
    threshold: number,
    messages: number[],
): void => {
    const expectedProduct = messages.reduce(
        (product, secret) => product * secret,
        1,
    );
    const { keyShares, commonPublicKey, prime, generator } = thresholdSetup(
        participantsCount,
        threshold,
    );
    const encryptedMessages = messages.map((secret) =>
        encrypt(secret, prime, generator, commonPublicKey),
    );
    const encryptedProduct = encryptedMessages.reduce(
        (product, encryptedMessage) =>
            multiplyEncryptedValues(product, encryptedMessage, prime),
        { c1: 1n, c2: 1n },
    );
    const selectedDecryptionShares = keyShares
        .sort(() => Math.random() - 0.5)
        .slice(0, threshold)
        .map(({ privateKey }) =>
            createDecryptionShare(encryptedProduct, privateKey, prime),
        );
    const combinedDecryptionShares = combineDecryptionShares(
        selectedDecryptionShares,
        prime,
    );
    const decryptedProduct = thresholdDecrypt(
        encryptedProduct,
        combinedDecryptionShares,
        prime,
    );
    expect(decryptedProduct).toBe(expectedProduct);
};

export const votingTest = (
    participantsCount: number,
    threshold: number,
    candidatesCount: number,
): void => {
    const { keyShares, commonPublicKey, prime, generator } = thresholdSetup(
        participantsCount,
        threshold,
    );
    const votesMatrix = Array.from({ length: participantsCount }, () =>
        Array.from({ length: candidatesCount }, () => getRandomScore(1, 10)),
    );
    const expectedProducts = Array.from(
        { length: candidatesCount },
        (_, candidateIndex) =>
            votesMatrix.reduce(
                (product, votes) => product * votes[candidateIndex],
                1,
            ),
    );
    const encryptedVotesMatrix = votesMatrix.map((votes) =>
        votes.map((vote) => encrypt(vote, prime, generator, commonPublicKey)),
    );
    const encryptedProducts = Array.from(
        { length: candidatesCount },
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
                createDecryptionShare(product, keyShare.privateKey, prime),
            ),
    );
    const decryptedProducts = partialDecryptionsMatrix.map(
        (decryptionShares) => {
            const combinedDecryptionShares = combineDecryptionShares(
                decryptionShares,
                prime,
            );
            const encryptedProduct =
                encryptedProducts[
                    partialDecryptionsMatrix.indexOf(decryptionShares)
                ];
            return thresholdDecrypt(
                encryptedProduct,
                combinedDecryptionShares,
                prime,
            );
        },
    );
    expect(decryptedProducts).toEqual(expectedProducts);
};
