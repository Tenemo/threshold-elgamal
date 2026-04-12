import { describe, expect, it } from 'vitest';

import {
    type EncodedPoint,
    InvalidGroupElementError,
    RISTRETTO_GROUP,
    ThresholdViolationError,
    UnsupportedSuiteError,
} from '#core';
import {
    derivePedersenShares,
    generateFeldmanCommitments,
    generatePedersenCommitments,
    verifyFeldmanShare,
    verifyPedersenShare,
} from '#vss';

const deriveShares = (
    polynomial: readonly bigint[],
    participantCount: number,
    q: bigint,
): readonly {
    readonly index: number;
    readonly value: bigint;
}[] => {
    if (!Number.isInteger(participantCount) || participantCount < 1) {
        throw new ThresholdViolationError(
            'Participant count must be a positive integer',
        );
    }

    return Array.from({ length: participantCount }, (_value, offset) => {
        const index = offset + 1;
        let result = 0n;

        for (
            let coefficientIndex = polynomial.length - 1;
            coefficientIndex >= 0;
            coefficientIndex -= 1
        ) {
            result =
                (((result * BigInt(index)) % q) +
                    polynomial[coefficientIndex]) %
                q;
        }

        return {
            index,
            value: result,
        };
    });
};

describe('verifiable secret sharing', () => {
    it('verifies Feldman shares against coefficient commitments', () => {
        const group = RISTRETTO_GROUP;
        const polynomial = [12345n, 67890n, 13579n] as const;
        const shares = deriveShares(polynomial, 5, group.q);
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
        const group = RISTRETTO_GROUP;
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
        const group = RISTRETTO_GROUP;
        const secretPolynomial = [12345n, 67890n, 13579n] as const;
        const blindingPolynomial = [22222n, 33333n, 44444n] as const;
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
            verifyPedersenShare(
                shares[0],
                {
                    commitments: [
                        'ff'.repeat(32) as EncodedPoint,
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
        expect(() => deriveShares(secretPolynomial, 0, group.q)).toThrow(
            ThresholdViolationError,
        );
        expect(() => deriveShares(secretPolynomial, 2.5, group.q)).toThrow(
            ThresholdViolationError,
        );
    });

    it('rejects altered group definitions in low-level VSS helpers', () => {
        const group = RISTRETTO_GROUP;
        const alteredGroup = {
            ...group,
            h: group.g,
        };
        const polynomial = [12345n, 67890n, 13579n] as const;

        expect(() =>
            generateFeldmanCommitments(polynomial, {
                ...group,
                g: group.h,
            }),
        ).toThrow(UnsupportedSuiteError);
        expect(() =>
            generatePedersenCommitments(polynomial, polynomial, alteredGroup),
        ).toThrow(UnsupportedSuiteError);
    });
});
