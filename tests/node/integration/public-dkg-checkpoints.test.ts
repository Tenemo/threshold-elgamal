import { beforeAll, describe, expect, it } from 'vitest';

import { runVotingFlowScenario } from '../../../tools/internal/voting-flow-harness.js';

import { signProtocolPayload, verifyDKGTranscript } from '#root';

const fixtureTimeoutMs = 240_000;

describe('public dkg checkpoints', () => {
    let checkpointedFixture: Awaited<ReturnType<typeof runVotingFlowScenario>>;

    beforeAll(async () => {
        checkpointedFixture = await runVotingFlowScenario({
            participantCount: 4,
            optionList: ['One', 'Two', 'Three'],
            participantVotes: [
                [1n, 2n, 3n],
                [4n, 5n, 6n],
                [7n, 8n, 9n],
                [10n, 1n, 2n],
            ],
            includePhaseCheckpoints: true,
        });
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
            expect(verified.qual).toEqual([1, 2, 3, 4]);
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
});
