import { expect } from 'vitest';

import { GROUPS } from './constants';
import { encrypt } from './elgamal';
import {
    generateIndividualKeyPair,
    combinePublicKeys,
    partialDecrypt,
    combinePartialDecryptions,
    thresholdDecrypt,
} from './thresholdElgamal';
import type { KeyPair } from './types';
import { multiplyEncryptedValues } from './utils';

export const getRandomScore = (min = 1, max = 10): number =>
    Math.floor(Math.random() * (max - min + 1)) + min;

export const thresholdSetup = (
    partiesCount: number,
    primeBits: 2048 | 3072 | 4096 = 2048,
): {
    keyPairs: KeyPair[];
    combinedPublicKey: bigint;
    prime: bigint;
    generator: bigint;
} => {
    const keyPairs = Array.from({ length: partiesCount }, () =>
        generateIndividualKeyPair(primeBits),
    );
    const publicKeys = keyPairs.map((kp) => kp.publicKey);
    const prime = GROUPS[`ffdhe${primeBits}`].prime;
    const generator = GROUPS[`ffdhe${primeBits}`].generator;
    const combinedPublicKey = combinePublicKeys(publicKeys, prime);

    return { keyPairs, combinedPublicKey, prime, generator };
};

export const homomorphicMultiplicationTest = (
    participantsCount: number,
    messages: number[],
): void => {
    const { keyPairs, combinedPublicKey, prime, generator } =
        thresholdSetup(participantsCount);

    const encryptedMessages = messages.map((message) =>
        encrypt(message, prime, generator, combinedPublicKey),
    );

    const encryptedProduct = encryptedMessages.reduce(
        (product, encryptedMessage) =>
            multiplyEncryptedValues(product, encryptedMessage, prime),
        { c1: 1n, c2: 1n },
    );

    const partialDecryptions = keyPairs.map((keyPair) =>
        partialDecrypt(encryptedProduct.c1, keyPair.privateKey, prime),
    );

    const combinedPartialDecryptions = combinePartialDecryptions(
        partialDecryptions,
        prime,
    );

    const decryptedProduct = thresholdDecrypt(
        encryptedProduct,
        combinedPartialDecryptions,
        prime,
    );

    const expectedProduct = messages.reduce(
        (product, message) => product * message,
        1,
    );

    expect(decryptedProduct).toBe(expectedProduct);
};
