import { describe, expect, it } from 'vitest';

import protocolVectors from '../../../test-vectors/protocol.json';

import { getGroup, type EncodedPoint, type GroupIdentifier } from '#core';
import type { ElgamalCiphertext } from '#elgamal';
import {
    verifyDLEQProof,
    verifyDisjunctiveProof,
    verifySchnorrProof,
    type ProofContext,
} from '#proofs';
import {
    canonicalizeElectionManifest,
    deriveSessionId,
    hashElectionManifest,
    verifyAndAggregateBallots,
    type BallotTranscriptEntry,
    type ElectionManifest,
} from '#protocol';

const toBigInt = (value: string): bigint => BigInt(value);

describe('protocol reproducibility vectors', () => {
    it('round-trips the frozen manifest and injective session derivation vectors', async () => {
        const manifest = protocolVectors.manifest as ElectionManifest;

        expect(canonicalizeElectionManifest(manifest)).toBe(
            protocolVectors.canonicalManifest,
        );
        await expect(hashElectionManifest(manifest)).resolves.toBe(
            protocolVectors.manifestHash,
        );
        await expect(
            deriveSessionId(
                protocolVectors.sessionInputs.left.manifestHash,
                protocolVectors.sessionInputs.left.rosterHash,
                protocolVectors.sessionInputs.left.randomNonce,
                protocolVectors.sessionInputs.left.timestamp,
            ),
        ).resolves.toBe(protocolVectors.sessionIds.left);
        await expect(
            deriveSessionId(
                protocolVectors.sessionInputs.right.manifestHash,
                protocolVectors.sessionInputs.right.rosterHash,
                protocolVectors.sessionInputs.right.randomNonce,
                protocolVectors.sessionInputs.right.timestamp,
            ),
        ).resolves.toBe(protocolVectors.sessionIds.right);
        expect(protocolVectors.sessionIds.left).not.toBe(
            protocolVectors.sessionIds.right,
        );
    });

    it('verifies the frozen Schnorr, DLEQ, and disjunctive proof vectors', async () => {
        const group = getGroup(protocolVectors.group as GroupIdentifier);

        await expect(
            verifySchnorrProof(
                {
                    challenge: toBigInt(
                        protocolVectors.schnorr.proof.challenge,
                    ),
                    response: toBigInt(protocolVectors.schnorr.proof.response),
                },
                protocolVectors.schnorr.statement as EncodedPoint,
                group,
                protocolVectors.schnorr.context as ProofContext,
            ),
        ).resolves.toBe(true);

        await expect(
            verifyDLEQProof(
                {
                    challenge: toBigInt(protocolVectors.dleq.proof.challenge),
                    response: toBigInt(protocolVectors.dleq.proof.response),
                },
                {
                    publicKey: protocolVectors.dleq.statement
                        .publicKey as EncodedPoint,
                    ciphertext: {
                        c1: protocolVectors.dleq.statement.ciphertext
                            .c1 as EncodedPoint,
                        c2: protocolVectors.dleq.statement.ciphertext
                            .c2 as EncodedPoint,
                    } as ElgamalCiphertext,
                    decryptionShare: protocolVectors.dleq.statement
                        .decryptionShare as EncodedPoint,
                },
                group,
                protocolVectors.dleq.context as ProofContext,
            ),
        ).resolves.toBe(true);

        await expect(
            verifyDisjunctiveProof(
                {
                    branches: protocolVectors.disjunctive.proof.branches.map(
                        (branch) => ({
                            challenge: toBigInt(branch.challenge),
                            response: toBigInt(branch.response),
                        }),
                    ),
                },
                {
                    c1: protocolVectors.disjunctive.ciphertext
                        .c1 as EncodedPoint,
                    c2: protocolVectors.disjunctive.ciphertext
                        .c2 as EncodedPoint,
                } as ElgamalCiphertext,
                protocolVectors.disjunctive.publicKey as EncodedPoint,
                protocolVectors.disjunctive.validValues.map(toBigInt),
                group,
                protocolVectors.disjunctive.context as ProofContext,
            ),
        ).resolves.toBe(true);
    });

    it('recomputes the frozen ballot aggregation vector', async () => {
        const group = getGroup(protocolVectors.group as GroupIdentifier);
        const ballots = protocolVectors.ballotAggregation.ballots.map(
            (ballot): BallotTranscriptEntry => ({
                voterIndex: ballot.voterIndex,
                optionIndex: ballot.optionIndex,
                ciphertext: {
                    c1: ballot.ciphertext.c1 as EncodedPoint,
                    c2: ballot.ciphertext.c2 as EncodedPoint,
                } as ElgamalCiphertext,
                proof: {
                    branches: ballot.proof.branches.map((branch) => ({
                        challenge: toBigInt(branch.challenge),
                        response: toBigInt(branch.response),
                    })),
                },
            }),
        );

        const aggregation = await verifyAndAggregateBallots({
            ballots,
            publicKey: protocolVectors.disjunctive.publicKey as EncodedPoint,
            validValues: protocolVectors.disjunctive.validValues.map(toBigInt),
            group,
            manifestHash: 'manifest-hash',
            sessionId: 'session-1',
            minimumBallotCount:
                protocolVectors.ballotAggregation.aggregate.ballotCount - 1,
        });

        expect(aggregation.transcriptHash).toBe(
            protocolVectors.ballotAggregation.transcriptHash,
        );
        expect(aggregation.aggregate.transcriptHash).toBe(
            protocolVectors.ballotAggregation.aggregate.transcriptHash,
        );
        expect(aggregation.aggregate.ballotCount).toBe(
            protocolVectors.ballotAggregation.aggregate.ballotCount,
        );
        expect(aggregation.aggregate.ciphertext).toEqual({
            c1: protocolVectors.ballotAggregation.aggregate.ciphertext.c1,
            c2: protocolVectors.ballotAggregation.aggregate.ciphertext.c2,
        });
    });
});
