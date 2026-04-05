import { describe, expect, it } from 'vitest';

import {
    addEncryptedValues,
    babyStepGiantStep,
    decryptAdditive,
    encryptAdditive,
    generateParameters,
    getGroup,
    InvalidGroupElementError,
    PlaintextDomainError,
} from '#root';

describe('additive ElGamal', () => {
    it('round-trips bounded additive messages', () => {
        const group = getGroup(2048);
        const { publicKey, privateKey } = generateParameters(group);

        for (const message of [0n, 1n, 42n, 1000n]) {
            const ciphertext = encryptAdditive(
                message,
                publicKey,
                group,
                1000n,
            );
            expect(decryptAdditive(ciphertext, privateKey, group, 1000n)).toBe(
                message,
            );
        }
    });

    it('rejects invalid additive plaintexts and public keys', () => {
        const group = getGroup(2048);
        const { publicKey } = generateParameters(group);

        expect(() => encryptAdditive(-1n, publicKey, group, 10n)).toThrow(
            PlaintextDomainError,
        );
        expect(() => encryptAdditive(11n, publicKey, group, 10n)).toThrow(
            PlaintextDomainError,
        );
        expect(() => encryptAdditive(1n, 1n, group, 10n)).toThrow(
            InvalidGroupElementError,
        );
    });

    it('rejects additive decryptions that exceed the supplied bound', () => {
        const group = getGroup(2048);
        const { publicKey, privateKey } = generateParameters(group);
        const ciphertext = encryptAdditive(11n, publicKey, group, 20n);

        expect(() =>
            decryptAdditive(ciphertext, privateKey, group, 10n),
        ).toThrow(PlaintextDomainError);
    });

    it('adds ciphertexts homomorphically', () => {
        const group = getGroup(2048);
        const { publicKey, privateKey } = generateParameters(group);
        const left = encryptAdditive(6n, publicKey, group, 20n);
        const right = encryptAdditive(7n, publicKey, group, 20n);

        const sum = addEncryptedValues(left, right, group);

        expect(decryptAdditive(sum, privateKey, group, 20n)).toBe(13n);
    });

    it('returns null when BSGS search space is too small', () => {
        const group = getGroup(2048);
        const encoded = group.g ** 0n;
        const target = (encoded * group.g) % group.p;

        expect(babyStepGiantStep(target, group.g, group.p, 0n)).toBeNull();
    });
});
