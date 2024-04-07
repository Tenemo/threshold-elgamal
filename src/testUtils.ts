import { expect } from 'vitest';

import { GROUPS } from './constants';
import { encrypt } from './elgamal';
import {
    generateKeyShares,
    combinePublicKeys,
    createDecryptionShare,
    combineDecryptionShares,
    thresholdDecrypt,
} from './thresholdElgamal';
import type { PartyKeyPair } from './types';
import { multiplyEncryptedValues } from './utils';

export const getRandomScore = (min = 1, max = 10): number =>
    Math.floor(Math.random() * (max - min + 1)) + min;

export const thresholdSetup = (
    partiesCount: number,
    threshold: number,
    primeBits: 2048 | 3072 | 4096 = 2048,
): {
    keyShares: PartyKeyPair[];
    combinedPublicKey: bigint;
    prime: bigint;
    generator: bigint;
} => {
    const keyShares = generateKeyShares(partiesCount, threshold, primeBits);
    const publicKeys = keyShares.map((ks) => ks.partyPublicKey);
    const prime = GROUPS[`ffdhe${primeBits}`].prime;
    const generator = GROUPS[`ffdhe${primeBits}`].generator;
    const combinedPublicKey = combinePublicKeys(publicKeys, prime);

    return { keyShares, combinedPublicKey, prime, generator };
};

export const testSecureEncryptionAndDecryption = (
    participantsCount: number,
    threshold: number,
    message: number,
): void => {
    const { keyShares, combinedPublicKey, prime, generator } = thresholdSetup(
        participantsCount,
        threshold,
    );

    const encryptedMessage = encrypt(
        message,
        prime,
        generator,
        combinedPublicKey,
    );

    const decryptionShares = keyShares
        .sort(() => Math.random() - 0.5)
        .slice(0, threshold)
        .map((keyShare) =>
            createDecryptionShare(
                encryptedMessage,
                keyShare.partyPrivateKey,
                prime,
            ),
        );

    const combinedDecryptionShares = combineDecryptionShares(
        decryptionShares,
        prime,
    );

    const decryptedMessage = thresholdDecrypt(
        encryptedMessage,
        combinedDecryptionShares,
        prime,
    );

    expect(decryptedMessage).toBe(message);
};

export const homomorphicMultiplicationTest = (
    participantsCount: number,
    threshold: number,
    messages: number[],
): void => {
    const expectedProduct = messages.reduce(
        (product, message) => product * message,
        1,
    );
    const { keyShares, combinedPublicKey, prime, generator } = thresholdSetup(
        participantsCount,
        threshold,
    );
    const encryptedMessages = messages.map((message) =>
        encrypt(message, prime, generator, combinedPublicKey),
    );
    const encryptedProduct = encryptedMessages.reduce(
        (product, encryptedMessage) =>
            multiplyEncryptedValues(product, encryptedMessage, prime),
        { c1: 1n, c2: 1n },
    );
    const decryptionShares = keyShares
        .sort(() => Math.random() - 0.5)
        .slice(0, threshold)
        .map((keyShare) =>
            createDecryptionShare(
                encryptedProduct,
                keyShare.partyPrivateKey,
                prime,
            ),
        );
    const combinedDecryptionShares = combineDecryptionShares(
        decryptionShares,
        prime,
    );
    const decryptedProduct = thresholdDecrypt(
        encryptedProduct,
        combinedDecryptionShares,
        prime,
    );
    expect(decryptedProduct).toBe(expectedProduct);
};
