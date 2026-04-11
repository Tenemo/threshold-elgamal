import { describe, expect, it } from 'vitest';

import thresholdVector from '../../../test-vectors/threshold.json';

import {
    type EncodedPoint,
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
import { encodePoint, multiplyBase } from '#src/core/ristretto';
import { createDecryptionShare } from '#src/threshold/decrypt';
import {
    combineDecryptionShares,
    createVerifiedDecryptionShare,
    dealerKeyGen,
    deriveSharesFromPolynomial,
    lagrangeCoefficient,
} from '#threshold';
const thresholdTestTimeoutMs = 60000;
const thresholdVectorGroup = thresholdVector.group as 'ristretto255';
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
            label: '2-of-3 on ristretto255',
            group: 'ristretto255' as const,
            threshold: 2,
            participantCount: 3,
            message: 9n,
        },
        {
            label: '3-of-5 on ristretto255',
            group: 'ristretto255' as const,
            threshold: 3,
            participantCount: 5,
            message: 11n,
        },
        {
            label: '5-of-10 on ristretto255',
            group: 'ristretto255' as const,
            threshold: 5,
            participantCount: 10,
            message: 13n,
        },
        {
            label: '26-of-51 on ristretto255',
            group: 'ristretto255' as const,
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
                );
                const ciphertext = encryptAdditive(
                    scenario.message,
                    keySet.publicKey,
                    scenario.message,
                );
                const decryptionShares = keySet.shares
                    .slice(0, scenario.threshold)
                    .map((share) => createDecryptionShare(ciphertext, share));
                expect(
                    combineDecryptionShares(
                        ciphertext,
                        decryptionShares,
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
            const keySet = dealerKeyGen(3, 5);
            const ciphertext = encryptAdditive(8n, keySet.publicKey, 8n);
            const subsets = choose(keySet.shares, 3);
            expect(subsets).toHaveLength(10);
            for (const subset of subsets) {
                const decryptionShares = subset.map((share) =>
                    createDecryptionShare(ciphertext, share),
                );
                expect(
                    combineDecryptionShares(ciphertext, decryptionShares, 8n),
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
            const group = getGroup(thresholdVectorGroup);
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
                    createDecryptionShare(ciphertext, share),
                );
                try {
                    expect(
                        combineDecryptionShares(
                            ciphertext,
                            decryptionShares,
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
        const keySet = dealerKeyGen(3, 5);
        const left = encryptAdditive(6n, keySet.publicKey, 20n);
        const right = encryptAdditive(7n, keySet.publicKey, 20n);
        const sum = addEncryptedValues(left, right);
        const decryptionShares = keySet.shares
            .slice(0, 3)
            .map((share) => createDecryptionShare(sum, share));
        expect(combineDecryptionShares(sum, decryptionShares, 20n)).toBe(13n);
    });
    it('handles k=n, k=1, plaintext zero, and maximum-score bounds', () => {
        const allRequired = dealerKeyGen(4, 4);
        const anySingle = dealerKeyGen(1, 4);
        const maxCiphertext = encryptAdditive(10n, allRequired.publicKey, 10n);
        const maxShares = allRequired.shares.map((share) =>
            createDecryptionShare(maxCiphertext, share),
        );
        expect(combineDecryptionShares(maxCiphertext, maxShares, 10n)).toBe(
            10n,
        );
        const zeroCiphertext = encryptAdditive(0n, anySingle.publicKey, 10n);
        const singleShare = createDecryptionShare(
            zeroCiphertext,
            anySingle.shares[0],
        );
        expect(
            combineDecryptionShares(zeroCiphertext, [singleShare], 10n),
        ).toBe(0n);
    });
    it('does not recover the correct plaintext when one required share is missing', () => {
        const keySet = dealerKeyGen(4, 4);
        const ciphertext = encryptAdditive(7n, keySet.publicKey, 7n);
        const partialShares = keySet.shares
            .slice(0, 3)
            .map((share) => createDecryptionShare(ciphertext, share));

        try {
            expect(
                combineDecryptionShares(ciphertext, partialShares, 7n),
            ).not.toBe(7n);
        } catch (error) {
            expect(error).toBeInstanceOf(PlaintextDomainError);
        }
    });
    it('rejects duplicate decryption-share indices and blank verified aggregates', () => {
        const keySet = dealerKeyGen(2, 3);
        const ciphertext = encryptAdditive(5n, keySet.publicKey, 10n);
        const decryptionShare = createDecryptionShare(
            ciphertext,
            keySet.shares[0],
        );
        expect(() =>
            combineDecryptionShares(
                ciphertext,
                [decryptionShare, decryptionShare],
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
            ),
        ).toThrow(InvalidShareError);
    });
    it('rejects malformed ciphertext and share inputs during threshold decryption', () => {
        const keySet = dealerKeyGen(2, 3);
        const ciphertext = encryptAdditive(5n, keySet.publicKey, 10n);
        expect(() =>
            createDecryptionShare(
                {
                    ...ciphertext,
                    c1: 'ff'.repeat(32) as EncodedPoint,
                },
                keySet.shares[0],
            ),
        ).toThrow(InvalidGroupElementError);
        expect(() =>
            createDecryptionShare(ciphertext, {
                ...keySet.shares[0],
                index: 0,
            }),
        ).toThrow(IndexOutOfRangeError);
        const validShare = createDecryptionShare(ciphertext, keySet.shares[0]);
        expect(() =>
            combineDecryptionShares(
                {
                    ...ciphertext,
                    c2: 'ff'.repeat(32) as EncodedPoint,
                },
                [validShare],
                10n,
            ),
        ).toThrow(InvalidGroupElementError);
        expect(() =>
            combineDecryptionShares(
                ciphertext,
                [{ ...validShare, index: 0 }],
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
                10n,
            ),
        ).toThrow(InvalidGroupElementError);
    });
    it('matches the frozen threshold vector', () => {
        const group = getGroup(thresholdVectorGroup);
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
        );
        const subsetShares = shares.filter((share) =>
            subsetIndices.includes(share.index),
        );
        const decryptionShares = subsetShares.map((share) =>
            createDecryptionShare(ciphertext, share),
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
                BigInt(thresholdVector.ciphertext.bound),
            ),
        ).toBe(BigInt(thresholdVector.recovered));
    });
    it('rejects invalid dealer-threshold parameters', () => {
        expect(() => dealerKeyGen(0, 3)).toThrow(ThresholdViolationError);
        expect(() => dealerKeyGen(4, 3)).toThrow(ThresholdViolationError);
    });
});
