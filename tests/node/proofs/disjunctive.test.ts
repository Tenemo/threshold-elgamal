import { describe, expect, it } from 'vitest';

import { createDeterministicSource } from '../../../dev-support/deterministic.js';

import { InvalidProofError, getGroup } from '#core';
import { encryptAdditiveWithRandomness } from '#elgamal';
import {
    createDisjunctiveProof,
    verifyDisjunctiveProof,
    type ProofContext,
} from '#proofs';
import { encodePoint, multiplyBase } from '#src/core/ristretto';

describe('disjunctive proofs', () => {
    const group = getGroup('ristretto255');
    const secret = 12345n;
    const publicKey = encodePoint(multiplyBase(secret));
    const validValues = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n] as const;
    const plaintext = 7n;
    const randomness = 42n;
    const ciphertext = encryptAdditiveWithRandomness(
        plaintext,
        publicKey,
        randomness,
        10n,
        group.name,
    );
    const context: ProofContext = {
        protocolVersion: 'v1',
        suiteId: group.name,
        manifestHash: 'manifest-1',
        sessionId: 'session-1',
        label: 'ballot-range',
        voterIndex: 3,
        optionIndex: 2,
    };

    it('verifies honest proofs over the score-voting domain', async () => {
        const proof = await createDisjunctiveProof(
            plaintext,
            randomness,
            ciphertext,
            publicKey,
            validValues,
            group,
            context,
            createDeterministicSource(),
        );

        await expect(
            verifyDisjunctiveProof(
                proof,
                ciphertext,
                publicKey,
                validValues,
                group,
                context,
            ),
        ).resolves.toBe(true);
    });

    it('rejects out-of-range plaintexts and cross-option or cross-voter replay', async () => {
        const proof = await createDisjunctiveProof(
            plaintext,
            randomness,
            ciphertext,
            publicKey,
            validValues,
            group,
            context,
            createDeterministicSource(),
        );

        await expect(
            createDisjunctiveProof(
                11n,
                randomness,
                ciphertext,
                publicKey,
                validValues,
                group,
                context,
                createDeterministicSource(),
            ),
        ).rejects.toBeInstanceOf(InvalidProofError);
        await expect(
            verifyDisjunctiveProof(
                proof,
                ciphertext,
                publicKey,
                validValues,
                group,
                { ...context, optionIndex: 5 },
            ),
        ).resolves.toBe(false);
        await expect(
            verifyDisjunctiveProof(
                proof,
                ciphertext,
                publicKey,
                validValues,
                group,
                { ...context, voterIndex: 5 },
            ),
        ).resolves.toBe(false);
    });

    it('rejects garbled branch data and malformed proof contexts', async () => {
        const proof = await createDisjunctiveProof(
            plaintext,
            randomness,
            ciphertext,
            publicKey,
            validValues,
            group,
            context,
            createDeterministicSource(),
        );

        await expect(
            verifyDisjunctiveProof(
                {
                    branches: proof.branches.slice(0, -1),
                },
                ciphertext,
                publicKey,
                validValues,
                group,
                context,
            ),
        ).resolves.toBe(false);
        await expect(
            verifyDisjunctiveProof(
                {
                    branches: proof.branches.map((branch, index) =>
                        index === 0
                            ? { ...branch, challenge: branch.challenge + 1n }
                            : branch,
                    ),
                },
                ciphertext,
                publicKey,
                validValues,
                group,
                context,
            ),
        ).resolves.toBe(false);
        await expect(
            createDisjunctiveProof(
                plaintext,
                randomness,
                ciphertext,
                publicKey,
                validValues,
                group,
                { ...context, voterIndex: 0 },
                createDeterministicSource(),
            ),
        ).rejects.toBeInstanceOf(InvalidProofError);
    });

    it('rejects branch scalars outside Z_q without throwing', async () => {
        const proof = await createDisjunctiveProof(
            plaintext,
            randomness,
            ciphertext,
            publicKey,
            validValues,
            group,
            context,
            createDeterministicSource(),
        );

        await expect(
            verifyDisjunctiveProof(
                {
                    branches: proof.branches.map((branch, index) =>
                        index === 0 ? { ...branch, challenge: -1n } : branch,
                    ),
                },
                ciphertext,
                publicKey,
                validValues,
                group,
                context,
            ),
        ).resolves.toBe(false);
        await expect(
            verifyDisjunctiveProof(
                {
                    branches: proof.branches.map((branch, index) =>
                        index === 1 ? { ...branch, response: group.q } : branch,
                    ),
                },
                ciphertext,
                publicKey,
                validValues,
                group,
                context,
            ),
        ).resolves.toBe(false);
    });
});
