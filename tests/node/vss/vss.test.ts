import { describe, expect, it } from 'vitest';

import {
    IndexOutOfRangeError,
    InvalidGroupElementError,
    InvalidScalarError,
    ThresholdViolationError,
    getGroup,
} from '#core';
import { deriveSharesFromPolynomial } from '#threshold';
import {
    derivePedersenShares,
    generateFeldmanCommitments,
    generatePedersenCommitments,
    verifyFeldmanShare,
    verifyPedersenShare,
} from '#vss';

describe('verifiable secret sharing', () => {
    it('verifies Feldman shares against coefficient commitments', () => {
        const group = getGroup(2048);
        const polynomial = [12345n, 67890n, 13579n] as const;
        const shares = deriveSharesFromPolynomial(polynomial, 5, group.q);
        const commitments = generateFeldmanCommitments(polynomial, group);

        expect(commitments.commitments).toHaveLength(3);

        for (const share of shares) {
            expect(verifyFeldmanShare(share, commitments, group)).toBe(true);
        }

        expect(
            verifyFeldmanShare(
                { index: shares[0].index, value: shares[0].value + 1n },
                commitments,
                group,
            ),
        ).toBe(false);
    });

    it('verifies Pedersen share pairs against coefficient commitments', () => {
        const group = getGroup(2048);
        const secretPolynomial = [12345n, 67890n, 13579n] as const;
        const blindingPolynomial = [22222n, 33333n, 44444n] as const;
        const commitments = generatePedersenCommitments(
            secretPolynomial,
            blindingPolynomial,
            group,
        );
        const shares = derivePedersenShares(
            secretPolynomial,
            blindingPolynomial,
            5,
            group.q,
        );

        expect(commitments.commitments).toHaveLength(3);

        for (const share of shares) {
            expect(verifyPedersenShare(share, commitments, group)).toBe(true);
        }

        expect(
            verifyPedersenShare(
                {
                    index: shares[0].index,
                    secretValue: shares[0].secretValue + 1n,
                    blindingValue: shares[0].blindingValue,
                },
                commitments,
                group,
            ),
        ).toBe(false);
        expect(
            verifyPedersenShare(
                {
                    index: shares[0].index,
                    secretValue: shares[0].secretValue,
                    blindingValue: shares[0].blindingValue + 1n,
                },
                commitments,
                group,
            ),
        ).toBe(false);
    });

    it('rejects malformed VSS inputs and garbled commitments', () => {
        const group = getGroup(2048);
        const secretPolynomial = [12345n, 67890n, 13579n] as const;
        const blindingPolynomial = [22222n, 33333n, 44444n] as const;
        const feldmanCommitments = generateFeldmanCommitments(
            secretPolynomial,
            group,
        );
        const pedersenCommitments = generatePedersenCommitments(
            secretPolynomial,
            blindingPolynomial,
            group,
        );
        const shares = derivePedersenShares(
            secretPolynomial,
            blindingPolynomial,
            3,
            group.q,
        );

        expect(() =>
            generatePedersenCommitments(
                secretPolynomial,
                blindingPolynomial.slice(0, -1),
                group,
            ),
        ).toThrow('same degree');
        expect(() =>
            verifyFeldmanShare(
                { index: 0, value: shares[0].secretValue },
                feldmanCommitments,
                group,
            ),
        ).toThrow(IndexOutOfRangeError);
        expect(() =>
            verifyPedersenShare(
                shares[0],
                {
                    commitments: [
                        0n,
                        ...pedersenCommitments.commitments.slice(1),
                    ],
                },
                group,
            ),
        ).toThrow(InvalidGroupElementError);
        expect(() =>
            derivePedersenShares(
                secretPolynomial,
                blindingPolynomial,
                0,
                group.q,
            ),
        ).toThrow(ThresholdViolationError);
        expect(() =>
            deriveSharesFromPolynomial(secretPolynomial, 0, group.q),
        ).toThrow(InvalidScalarError);
        expect(() =>
            deriveSharesFromPolynomial(secretPolynomial, 2.5, group.q),
        ).toThrow(InvalidScalarError);
    });
});
