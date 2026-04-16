import { beforeAll, describe, expect, it } from 'vitest';

import { runVotingFlowScenario } from '../../../tools/internal/voting-flow-harness';

import {
    createFeldmanCommitmentPayload,
    createKeyDerivationConfirmationPayload,
    createPhaseCheckpointPayload,
    createSchnorrProof,
    deriveJointPublicKey,
    generateFeldmanCommitments,
    hashProtocolTranscript,
    RISTRETTO_GROUP,
    SHIPPED_PROTOCOL_VERSION,
    signProtocolPayload,
    verifyDKGTranscript,
    type SignedPayload,
} from '#root';

const fixtureTimeoutMs = 240_000;

type VotingFlowFixture = Awaited<ReturnType<typeof runVotingFlowScenario>>;

const replacePhaseCheckpointPayloads = async (input: {
    readonly checkpointPhase: 0 | 1 | 2 | 3;
    readonly fixture: VotingFlowFixture;
    readonly qualifiedParticipantIndices: readonly number[];
    readonly signerIndices: readonly number[];
}): Promise<readonly SignedPayload[]> => [
    ...input.fixture.dkgTranscript.filter(
        (entry) =>
            entry.payload.messageType !== 'phase-checkpoint' ||
            entry.payload.checkpointPhase !== input.checkpointPhase,
    ),
    ...(await Promise.all(
        input.signerIndices.map((participantIndex) =>
            createPhaseCheckpointPayload(
                input.fixture.participants[participantIndex - 1].auth
                    .privateKey,
                {
                    checkpointPhase: input.checkpointPhase,
                    manifestHash: input.fixture.manifestHash,
                    participantIndex,
                    qualifiedParticipantIndices:
                        input.qualifiedParticipantIndices,
                    sessionId: input.fixture.sessionId,
                    transcript: input.fixture.dkgTranscript,
                },
            ),
        ),
    )),
];

const buildIdentityJointKeyTranscript = async (
    fixture: VotingFlowFixture,
): Promise<readonly SignedPayload[]> => {
    const identityPolynomials = [
        [1n, 4n],
        [2n, 5n],
        [RISTRETTO_GROUP.q - 3n, 6n],
    ] as const;
    const rewrittenFeldmanEntries = await Promise.all(
        fixture.participants.map(async (participant, participantOffset) => {
            const polynomial = identityPolynomials[participantOffset];
            const generatedCommitments = generateFeldmanCommitments(
                polynomial,
                RISTRETTO_GROUP,
            );
            const proofs = await Promise.all(
                polynomial.map(async (coefficient, coefficientOffset) => {
                    const coefficientIndex = coefficientOffset + 1;
                    const proof = await createSchnorrProof(
                        coefficient,
                        generatedCommitments.commitments[coefficientOffset],
                        RISTRETTO_GROUP,
                        {
                            protocolVersion: SHIPPED_PROTOCOL_VERSION,
                            suiteId: RISTRETTO_GROUP.name,
                            manifestHash: fixture.manifestHash,
                            sessionId: fixture.sessionId,
                            label: 'feldman-coefficient-proof',
                            participantIndex: participant.index,
                            coefficientIndex,
                        },
                    );

                    return {
                        coefficientIndex,
                        challenge: proof.challenge,
                        response: proof.response,
                    };
                }),
            );

            return {
                commitments: generatedCommitments.commitments,
                payload: await createFeldmanCommitmentPayload(
                    participant.auth.privateKey,
                    {
                        sessionId: fixture.sessionId,
                        manifestHash: fixture.manifestHash,
                        participantIndex: participant.index,
                        commitments: generatedCommitments.commitments,
                        proofs,
                    },
                ),
            };
        }),
    );
    const transcriptWithoutFinalization = fixture.dkgTranscript.filter(
        (entry) =>
            entry.payload.messageType !== 'feldman-commitment' &&
            entry.payload.messageType !== 'key-derivation-confirmation',
    );
    const transcriptBeforeConfirmations = [
        ...transcriptWithoutFinalization,
        ...rewrittenFeldmanEntries.map((entry) => entry.payload),
    ];
    const identityJointPublicKey = deriveJointPublicKey(
        rewrittenFeldmanEntries.map((entry, participantOffset) => ({
            dealerIndex: participantOffset + 1,
            commitments: entry.commitments,
        })),
        RISTRETTO_GROUP,
    );
    const dkgTranscriptHash = await hashProtocolTranscript(
        transcriptBeforeConfirmations.map((entry) => entry.payload),
        RISTRETTO_GROUP.byteLength,
    );
    const confirmations = await Promise.all(
        fixture.participants.map((participant) =>
            createKeyDerivationConfirmationPayload(
                participant.auth.privateKey,
                {
                    sessionId: fixture.sessionId,
                    manifestHash: fixture.manifestHash,
                    participantIndex: participant.index,
                    dkgTranscriptHash,
                    publicKey: identityJointPublicKey,
                },
            ),
        ),
    );

    return [...transcriptBeforeConfirmations, ...confirmations];
};

describe('public dkg checkpoints', () => {
    let checkpointedFixture: VotingFlowFixture;
    let checkpointedComplaintFixture: VotingFlowFixture;
    let identityFixture: VotingFlowFixture;

    beforeAll(async () => {
        [checkpointedFixture, checkpointedComplaintFixture, identityFixture] =
            await Promise.all([
                runVotingFlowScenario({
                    participantCount: 4,
                    optionList: ['One', 'Two', 'Three'],
                    participantVotes: [
                        [1n, 2n, 3n],
                        [4n, 5n, 6n],
                        [7n, 8n, 9n],
                        [10n, 1n, 2n],
                    ],
                    includePhaseCheckpoints: true,
                }),
                runVotingFlowScenario({
                    participantCount: 4,
                    optionList: ['One', 'Two', 'Three'],
                    participantVotes: [
                        [1n, 2n, 3n],
                        [4n, 5n, 6n],
                        [7n, 8n, 9n],
                        [10n, 1n, 2n],
                    ],
                    includePhaseCheckpoints: true,
                    dkgComplaint: {
                        dealerIndex: 4,
                        complainantIndex: 2,
                        outcome: 'accepted',
                        reason: 'aes-gcm-failure',
                    },
                }),
                runVotingFlowScenario({
                    participantCount: 3,
                    optionList: ['One', 'Two'],
                    participantVotes: [
                        [1n, 2n],
                        [3n, 4n],
                        [5n, 6n],
                    ],
                }),
            ]);
    }, fixtureTimeoutMs);

    it(
        'verifies a checkpointed DKG transcript and exposes the finalized checkpoint set',
        async () => {
            const verified = await verifyDKGTranscript({
                manifest: checkpointedFixture.manifest,
                sessionId: checkpointedFixture.sessionId,
                transcript: checkpointedFixture.dkgTranscript,
            });

            expect(
                verified.phaseCheckpoints.map(
                    (checkpoint) => checkpoint.payload.checkpointPhase,
                ),
            ).toEqual([0, 1, 2, 3]);
            expect(
                verified.phaseCheckpoints.map(
                    (checkpoint) => checkpoint.signatures.length,
                ),
            ).toEqual([4, 4, 4, 4]);
            expect(verified.qualifiedParticipantIndices).toEqual([1, 2, 3, 4]);
        },
        fixtureTimeoutMs,
    );

    it(
        'verifies complaint-driven checkpoint qualified-participant reduction when complaints justify the shrinkage',
        async () => {
            const verified = await verifyDKGTranscript({
                manifest: checkpointedComplaintFixture.manifest,
                sessionId: checkpointedComplaintFixture.sessionId,
                transcript: checkpointedComplaintFixture.dkgTranscript,
            });

            expect(
                verified.phaseCheckpoints.map(
                    (checkpoint) => checkpoint.signatures.length,
                ),
            ).toEqual([4, 4, 3, 3]);
            expect(verified.qualifiedParticipantIndices).toEqual([1, 2, 3]);
        },
        fixtureTimeoutMs,
    );

    it(
        'rejects transcripts that enter checkpoint mode without a threshold-supported phase checkpoint for every phase',
        async () => {
            const transcriptWithoutPhase2 =
                checkpointedFixture.dkgTranscript.filter(
                    (entry) =>
                        entry.payload.messageType !== 'phase-checkpoint' ||
                        entry.payload.checkpointPhase !== 2,
                );

            await expect(
                verifyDKGTranscript({
                    manifest: checkpointedFixture.manifest,
                    sessionId: checkpointedFixture.sessionId,
                    transcript: transcriptWithoutPhase2,
                }),
            ).rejects.toThrow(
                'Missing threshold-supported phase checkpoint for phase 2',
            );
        },
        fixtureTimeoutMs,
    );

    it(
        'rejects threshold-supported checkpoints whose signed transcript hash does not match the closed phase snapshot',
        async () => {
            const tamperedParticipantIndices = new Set([1, 2, 3]);
            const transcriptWithBadPhase3Checkpoint = await Promise.all(
                checkpointedFixture.dkgTranscript.map(async (entry) => {
                    if (
                        entry.payload.messageType !== 'phase-checkpoint' ||
                        entry.payload.checkpointPhase !== 3 ||
                        !tamperedParticipantIndices.has(
                            entry.payload.participantIndex,
                        )
                    ) {
                        return entry;
                    }

                    return signProtocolPayload(
                        checkpointedFixture.participants[
                            entry.payload.participantIndex - 1
                        ].auth.privateKey,
                        {
                            ...entry.payload,
                            checkpointTranscriptHash: 'aa'.repeat(32),
                        },
                    );
                }),
            );

            await expect(
                verifyDKGTranscript({
                    manifest: checkpointedFixture.manifest,
                    sessionId: checkpointedFixture.sessionId,
                    transcript: transcriptWithBadPhase3Checkpoint,
                }),
            ).rejects.toThrow(
                'Phase 3 checkpoint transcript hash does not match the signed transcript snapshot',
            );
        },
        fixtureTimeoutMs,
    );

    it(
        'rejects phase 1 checkpoints that silently shrink the qualified participant set without complaint-driven justification',
        async () => {
            const transcriptWithShrunkPhase1Qual =
                await replacePhaseCheckpointPayloads({
                    fixture: checkpointedFixture,
                    checkpointPhase: 1,
                    qualifiedParticipantIndices: [1, 2],
                    signerIndices: [1, 2],
                });

            await expect(
                verifyDKGTranscript({
                    manifest: checkpointedFixture.manifest,
                    sessionId: checkpointedFixture.sessionId,
                    transcript: transcriptWithShrunkPhase1Qual,
                }),
            ).rejects.toThrow(
                'Phase 1 checkpoint qualified participant set does not match the verifier-computed active participant set',
            );
        },
        fixtureTimeoutMs,
    );

    it(
        'rejects phase 3 checkpoints that shrink the qualified participant set below the complaint-bounded active set',
        async () => {
            const transcriptWithShrunkPhase3Qual =
                await replacePhaseCheckpointPayloads({
                    fixture: checkpointedFixture,
                    checkpointPhase: 3,
                    qualifiedParticipantIndices: [1, 2],
                    signerIndices: [1, 2],
                });

            await expect(
                verifyDKGTranscript({
                    manifest: checkpointedFixture.manifest,
                    sessionId: checkpointedFixture.sessionId,
                    transcript: transcriptWithShrunkPhase3Qual,
                }),
            ).rejects.toThrow(
                'Phase 3 checkpoint qualified participant set does not match the verifier-computed active participant set',
            );
        },
        fixtureTimeoutMs,
    );

    it(
        'rejects standalone DKG transcripts whose derived joint public key is the identity element',
        async () => {
            const transcriptWithIdentityJointKey =
                await buildIdentityJointKeyTranscript(identityFixture);

            await expect(
                verifyDKGTranscript({
                    manifest: identityFixture.manifest,
                    sessionId: identityFixture.sessionId,
                    transcript: transcriptWithIdentityJointKey,
                }),
            ).rejects.toThrow(
                'Derived joint public key must not be the identity element',
            );
        },
        fixtureTimeoutMs,
    );
});
