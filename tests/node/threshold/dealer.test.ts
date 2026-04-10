import { describe, expect, it } from 'vitest';

import { encodePoint, multiplyBase } from '../../../src/core/ristretto.js';
import { createDecryptionShare } from '../../../src/threshold/decrypt.js';
import thresholdVector from '../../../test-vectors/threshold.json';

import {
    type EncodedPoint,
    type GroupIdentifier,
    InvalidGroupElementError,
    InvalidShareError,
    IndexOutOfRangeError,
    PlaintextDomainError,
    ThresholdViolationError,
    getGroup,
} from '#core';
import {
    addEncryptedValues,
    encryptAdditive,
    encryptAdditiveWithRandomness,
} from '#elgamal';
import type { ElgamalCiphertext } from '#elgamal';
import {
    combineDecryptionShares,
    createVerifiedDecryptionShare,
    dealerKeyGen,
    deriveSharesFromPolynomial,
    lagrangeCoefficient,
} from '#threshold';

const thresholdTestTimeoutMs = 60_000;

const choose = <T>(items: readonly T[], size: number): T[][] => {
    if (size === 0) {
        return [[]];
    }

    if (size > items.length) {
        return [];
    }

    if (size === items.length) {
        return [items.slice()];
    }

    const [first, ...rest] = items;

    return [
        ...choose(rest, size - 1).map((tail) => [first, ...tail]),
        ...choose(rest, size),
    ];
};

describe('dealer-based threshold decryption', () => {
    const vectorCiphertext = (): ElgamalCiphertext => ({
        c1: thresholdVector.ciphertext.c1 as EncodedPoint,
        c2: thresholdVector.ciphertext.c2 as EncodedPoint,
    });

    const roundTripScenarios = [
        {
            label: '2-of-3 with the beta alias 2048',
            group: 2048 as const,
            threshold: 2,
            participantCount: 3,
            message: 9n,
        },
        {
            label: '3-of-5 with the beta alias 3072',
            group: 3072 as const,
            threshold: 3,
            participantCount: 5,
            message: 11n,
        },
        {
            label: '5-of-10 with the beta alias 4096',
            group: 4096 as const,
            threshold: 5,
            participantCount: 10,
            message: 13n,
        },
        {
            label: '26-of-51 with the beta alias 2048',
            group: 2048 as const,
            threshold: 26,
            participantCount: 51,
            message: 10n,
        },
    ] as const;

    for (const scenario of roundTripScenarios) {
        it(
            `round-trips representative threshold settings for ${scenario.label}`,
            () => {
                const keySet = dealerKeyGen(
                    scenario.threshold,
                    scenario.participantCount,
                    scenario.group,
                );
                const ciphertext = encryptAdditive(
                    scenario.message,
                    keySet.publicKey,
                    scenario.group,
                    scenario.message,
                );
                const decryptionShares = keySet.shares
                    .slice(0, scenario.threshold)
                    .map((share) =>
                        createDecryptionShare(ciphertext, share, keySet.group),
                    );

                expect(
                    combineDecryptionShares(
                        ciphertext,
                        decryptionShares,
                        keySet.group,
                        scenario.message,
                    ),
                ).toBe(scenario.message);
            },
            thresholdTestTimeoutMs,
        );
    }

    it(
        'recovers the same plaintext for every 3-of-5 subset',
        {
            timeout: thresholdTestTimeoutMs,
        },
        () => {
            const keySet = dealerKeyGen(3, 5, 2048);
            const ciphertext = encryptAdditive(8n, keySet.publicKey, 2048, 8n);
            const subsets = choose(keySet.shares, 3);

            expect(subsets).toHaveLength(10);

            for (const subset of subsets) {
                const decryptionShares = subset.map((share) =>
                    createDecryptionShare(ciphertext, share, keySet.group),
                );

                expect(
                    combineDecryptionShares(
                        ciphertext,
                        decryptionShares,
                        keySet.group,
                        8n,
                    ),
                ).toBe(8n);
            }
        },
    );

    it(
        'does not recover the correct plaintext with insufficient shares',
        {
            timeout: thresholdTestTimeoutMs,
        },
        () => {
            const group = getGroup(thresholdVector.group as GroupIdentifier);
            const polynomial = thresholdVector.polynomial.map((value) =>
                BigInt(value),
            );
            const shares = deriveSharesFromPolynomial(
                polynomial,
                thresholdVector.participantCount,
                group.q,
            );
            const ciphertext = vectorCiphertext();

            for (const subset of choose(shares, 2)) {
                const decryptionShares = subset.map((share) =>
                    createDecryptionShare(ciphertext, share, group),
                );

                try {
                    expect(
                        combineDecryptionShares(
                            ciphertext,
                            decryptionShares,
                            group,
                            BigInt(thresholdVector.ciphertext.bound),
                        ),
                    ).not.toBe(BigInt(thresholdVector.ciphertext.message));
                } catch (error) {
                    expect(error).toBeInstanceOf(PlaintextDomainError);
                }
            }
        },
    );

    it('preserves additive homomorphism under threshold decryption', () => {
        const keySet = dealerKeyGen(3, 5, 3072);
        const left = encryptAdditive(6n, keySet.publicKey, 3072, 20n);
        const right = encryptAdditive(7n, keySet.publicKey, 3072, 20n);
        const sum = addEncryptedValues(left, right, 3072);
        const decryptionShares = keySet.shares
            .slice(0, 3)
            .map((share) => createDecryptionShare(sum, share, keySet.group));

        expect(
            combineDecryptionShares(sum, decryptionShares, keySet.group, 20n),
        ).toBe(13n);
    });

    it('handles k=n, k=1, plaintext zero, and maximum-score bounds', () => {
        const allRequired = dealerKeyGen(4, 4, 2048);
        const anySingle = dealerKeyGen(1, 4, 2048);

        const maxCiphertext = encryptAdditive(
            10n,
            allRequired.publicKey,
            2048,
            10n,
        );
        const maxShares = allRequired.shares.map((share) =>
            createDecryptionShare(maxCiphertext, share, allRequired.group),
        );
        expect(
            combineDecryptionShares(
                maxCiphertext,
                maxShares,
                allRequired.group,
                10n,
            ),
        ).toBe(10n);

        const zeroCiphertext = encryptAdditive(
            0n,
            anySingle.publicKey,
            2048,
            10n,
        );
        const singleShare = createDecryptionShare(
            zeroCiphertext,
            anySingle.shares[0],
            anySingle.group,
        );
        expect(
            combineDecryptionShares(
                zeroCiphertext,
                [singleShare],
                anySingle.group,
                10n,
            ),
        ).toBe(0n);
    });

    it('rejects duplicate decryption-share indices and blank verified aggregates', () => {
        const keySet = dealerKeyGen(2, 3, 2048);
        const ciphertext = encryptAdditive(5n, keySet.publicKey, 2048, 10n);
        const decryptionShare = createDecryptionShare(
            ciphertext,
            keySet.shares[0],
            keySet.group,
        );

        expect(() =>
            combineDecryptionShares(
                ciphertext,
                [decryptionShare, decryptionShare],
                keySet.group,
                10n,
            ),
        ).toThrow(InvalidShareError);

        expect(() =>
            createVerifiedDecryptionShare(
                {
                    transcriptHash: '   ',
                    ciphertext,
                    ballotCount: 1,
                } as unknown as Parameters<
                    typeof createVerifiedDecryptionShare
                >[0],
                keySet.shares[0],
                keySet.group,
            ),
        ).toThrow(InvalidShareError);
    });

    it('rejects malformed ciphertext and share inputs during threshold decryption', () => {
        const keySet = dealerKeyGen(2, 3, 2048);
        const ciphertext = encryptAdditive(5n, keySet.publicKey, 2048, 10n);

        expect(() =>
            createDecryptionShare(
                {
                    ...ciphertext,
                    c1: 'ff'.repeat(32) as EncodedPoint,
                },
                keySet.shares[0],
                keySet.group,
            ),
        ).toThrow(InvalidGroupElementError);
        expect(() =>
            createDecryptionShare(
                ciphertext,
                { ...keySet.shares[0], index: 0 },
                keySet.group,
            ),
        ).toThrow(IndexOutOfRangeError);

        const validShare = createDecryptionShare(
            ciphertext,
            keySet.shares[0],
            keySet.group,
        );

        expect(() =>
            combineDecryptionShares(
                {
                    ...ciphertext,
                    c2: 'ff'.repeat(32) as EncodedPoint,
                },
                [validShare],
                keySet.group,
                10n,
            ),
        ).toThrow(InvalidGroupElementError);
        expect(() =>
            combineDecryptionShares(
                ciphertext,
                [{ ...validShare, index: 0 }],
                keySet.group,
                10n,
            ),
        ).toThrow(IndexOutOfRangeError);
        expect(() =>
            combineDecryptionShares(
                ciphertext,
                [
                    {
                        ...validShare,
                        value: 'ff'.repeat(32) as EncodedPoint,
                    },
                ],
                keySet.group,
                10n,
            ),
        ).toThrow(InvalidGroupElementError);
    });

    it('matches the frozen threshold vector', () => {
        const group = getGroup(thresholdVector.group as GroupIdentifier);
        const polynomial = thresholdVector.polynomial.map((value) =>
            BigInt(value),
        );
        const shares = deriveSharesFromPolynomial(
            polynomial,
            thresholdVector.participantCount,
            group.q,
        );
        const subsetIndices = thresholdVector.subsetIndices;
        const ciphertext = vectorCiphertext();
        const regeneratedCiphertext = encryptAdditiveWithRandomness(
            BigInt(thresholdVector.ciphertext.message),
            thresholdVector.publicKey as EncodedPoint,
            BigInt(thresholdVector.ciphertext.randomness),
            BigInt(thresholdVector.ciphertext.bound),
            group.name,
        );
        const subsetShares = shares.filter((share) =>
            subsetIndices.includes(share.index),
        );
        const decryptionShares = subsetShares.map((share) =>
            createDecryptionShare(ciphertext, share, group),
        );

        expect(thresholdVector.publicKey).toBe(
            encodePoint(multiplyBase(polynomial[0])),
        );
        expect(regeneratedCiphertext).toEqual(ciphertext);
        expect(
            shares.map((share) => ({
                index: share.index,
                value: share.value.toString(),
            })),
        ).toEqual(thresholdVector.shares);
        expect(
            shares.map((share) => ({
                index: share.index,
                value: encodePoint(multiplyBase(share.value)),
            })),
        ).toEqual(thresholdVector.participantPublicKeys);
        expect(
            decryptionShares.map((share) => ({
                index: share.index,
                value: share.value,
            })),
        ).toEqual(thresholdVector.decryptionShares);
        expect(
            subsetIndices.map((index) => ({
                index,
                value: lagrangeCoefficient(
                    BigInt(index),
                    subsetIndices.map((item) => BigInt(item)),
                    group.q,
                ).toString(),
            })),
        ).toEqual(thresholdVector.lagrangeCoefficients);
        expect(
            combineDecryptionShares(
                ciphertext,
                decryptionShares,
                group,
                BigInt(thresholdVector.ciphertext.bound),
            ),
        ).toBe(BigInt(thresholdVector.recovered));
    });

    it('rejects invalid dealer-threshold parameters', () => {
        expect(() => dealerKeyGen(0, 3, 2048)).toThrow(ThresholdViolationError);
        expect(() => dealerKeyGen(4, 3, 2048)).toThrow(ThresholdViolationError);
    });
});
