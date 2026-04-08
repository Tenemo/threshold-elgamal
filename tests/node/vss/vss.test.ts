import { describe, expect, it } from 'vitest';

import { getGroup } from '#core';
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
});
