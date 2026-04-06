import { describe, expect, it } from 'vitest';

import plainElgamalVectors from '../../../test-vectors/plain-elgamal.json';

import {
    addEncryptedValues,
    assertValidAdditiveCiphertext,
    assertValidFreshAdditiveCiphertext,
    babyStepGiantStep,
    decryptAdditive,
    encryptAdditive,
    encryptAdditiveWithRandomness,
    generateParameters,
    generateParametersWithPrivateKey,
    getGroup,
    InvalidGroupElementError,
    InvalidScalarError,
    PlaintextDomainError,
    UnsupportedSuiteError,
} from '#root';

describe('additive ElGamal', () => {
    it('round-trips bounded additive messages', () => {
        const { publicKey, privateKey } = generateParameters(2048);

        for (const message of [0n, 1n, 42n, 1000n]) {
            const ciphertext = encryptAdditive(message, publicKey, 2048, 1000n);
            expect(decryptAdditive(ciphertext, privateKey, 2048, 1000n)).toBe(
                message,
            );
        }
    });

    it('rejects invalid additive plaintexts and public keys', () => {
        expect.assertions(3);

        const { publicKey } = generateParameters(2048);

        expect(() => encryptAdditive(-1n, publicKey, 2048, 10n)).toThrow(
            PlaintextDomainError,
        );
        expect(() => encryptAdditive(11n, publicKey, 2048, 10n)).toThrow(
            PlaintextDomainError,
        );
        expect(() => encryptAdditive(1n, 1n, 2048, 10n)).toThrow(
            InvalidGroupElementError,
        );
    });

    it('rejects additive decryptions that exceed the supplied bound', () => {
        const { publicKey, privateKey } = generateParameters(2048);
        const ciphertext = encryptAdditive(11n, publicKey, 2048, 20n);

        expect(() =>
            decryptAdditive(ciphertext, privateKey, 2048, 10n),
        ).toThrow(PlaintextDomainError);
    });

    it('adds ciphertexts homomorphically', () => {
        const { publicKey, privateKey } = generateParameters(2048);
        const left = encryptAdditive(6n, publicKey, 2048, 20n);
        const right = encryptAdditive(7n, publicKey, 2048, 20n);

        const sum = addEncryptedValues(left, right, 2048);

        expect(decryptAdditive(sum, privateKey, 2048, 20n)).toBe(13n);
    });

    it('accepts additive aggregates with subgroup identity in c1', () => {
        const group = getGroup(2048);
        const { publicKey, privateKey } = generateParametersWithPrivateKey(
            5n,
            2048,
        );
        const left = encryptAdditiveWithRandomness(
            6n,
            publicKey,
            7n,
            20n,
            2048,
        );
        const right = encryptAdditiveWithRandomness(
            7n,
            publicKey,
            group.q - 7n,
            20n,
            2048,
        );

        const sum = addEncryptedValues(left, right, 2048);

        expect(sum.c1).toBe(1n);
        expect(() => assertValidAdditiveCiphertext(sum, group)).not.toThrow();
        expect(() => assertValidFreshAdditiveCiphertext(sum, group)).toThrow(
            InvalidGroupElementError,
        );
        expect(decryptAdditive(sum, privateKey, 2048, 20n)).toBe(13n);
    });

    it('accepts additive neutral accumulators', () => {
        const { publicKey, privateKey } = generateParameters(2048);
        const ciphertext = encryptAdditive(11n, publicKey, 2048, 20n);
        const sum = addEncryptedValues({ c1: 1n, c2: 1n }, ciphertext, 2048);

        expect(decryptAdditive(sum, privateKey, 2048, 20n)).toBe(11n);
    });

    it('requires an explicit additive bound', () => {
        const { publicKey, privateKey } = generateParameters(2048);
        const ciphertext = encryptAdditive(1n, publicKey, 2048, 10n);
        const encryptAdditiveUnchecked = encryptAdditive as (
            ...args: unknown[]
        ) => unknown;
        const decryptAdditiveUnchecked = decryptAdditive as (
            ...args: unknown[]
        ) => unknown;

        expect(() => encryptAdditiveUnchecked(1n, publicKey, 2048)).toThrow(
            InvalidScalarError,
        );
        expect(() =>
            decryptAdditiveUnchecked(ciphertext, privateKey, 2048),
        ).toThrow(InvalidScalarError);
    });

    it('matches the frozen additive vectors for every shipped group', () => {
        for (const [groupName, vector] of Object.entries(
            plainElgamalVectors.groups,
        )) {
            const group = getGroup(groupName as never);
            const additiveVector = vector.additive;
            const keyPair = generateParametersWithPrivateKey(
                BigInt(vector.privateKey),
                group.name,
            );
            const ciphertext = encryptAdditiveWithRandomness(
                BigInt(additiveVector.message),
                keyPair.publicKey,
                BigInt(additiveVector.randomness),
                BigInt(additiveVector.bound),
                group.name,
            );

            expect(ciphertext).toEqual({
                c1: BigInt(additiveVector.c1),
                c2: BigInt(additiveVector.c2),
            });
            expect(
                decryptAdditive(
                    ciphertext,
                    keyPair.privateKey,
                    group.name,
                    BigInt(additiveVector.bound),
                ),
            ).toBe(BigInt(additiveVector.message));
        }
    });

    it('matches the frozen additive homomorphic vectors', () => {
        for (const [groupName, vector] of Object.entries(
            plainElgamalVectors.groups,
        )) {
            const group = getGroup(groupName as never);
            const keyPair = generateParametersWithPrivateKey(
                BigInt(vector.privateKey),
                group.name,
            );
            const left = encryptAdditiveWithRandomness(
                BigInt(vector.additive.left.message),
                keyPair.publicKey,
                BigInt(vector.additive.left.randomness),
                BigInt(vector.additive.left.bound),
                group.name,
            );
            const right = encryptAdditiveWithRandomness(
                BigInt(vector.additive.right.message),
                keyPair.publicKey,
                BigInt(vector.additive.right.randomness),
                BigInt(vector.additive.right.bound),
                group.name,
            );
            const sum = addEncryptedValues(left, right, group.name);

            expect(sum).toEqual({
                c1: BigInt(vector.additive.sum.c1),
                c2: BigInt(vector.additive.sum.c2),
            });
            expect(
                decryptAdditive(
                    sum,
                    keyPair.privateKey,
                    group.name,
                    BigInt(vector.additive.sum.bound),
                ),
            ).toBe(BigInt(vector.additive.sum.message));
        }
    });

    it('rejects arbitrary group objects at runtime', () => {
        const group = getGroup(2048);
        const { publicKey } = generateParameters(2048);

        expect(() =>
            encryptAdditive(7n, publicKey, group as never, 10n),
        ).toThrow(UnsupportedSuiteError);
    });

    it('rejects invalid deterministic randomness', () => {
        const { publicKey } = generateParameters(2048);

        expect(() =>
            encryptAdditiveWithRandomness(7n, publicKey, 0n, 20n, 2048),
        ).toThrow(InvalidScalarError);
    });

    it('returns null when BSGS search space is too small', () => {
        const group = getGroup(2048);
        const encoded = group.g ** 0n;
        const target = (encoded * group.g) % group.p;

        expect(babyStepGiantStep(target, group.g, group.p, 0n)).toBeNull();
    });
});
