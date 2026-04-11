import { describe, expect, it } from 'vitest';

import {
    type CompletedVotingFlowResult,
    runVotingFlowScenario,
    type VotingFlowScenario,
} from '../../../dev-support/voting-flow-harness.js';

const scenarioTimeoutMs = 180_000;

const completedScenarios: readonly (VotingFlowScenario & {
    readonly expectedConfirmationCount?: number;
    readonly expectedCheckpointPhases?: readonly number[];
    readonly expectedQual: readonly number[];
    readonly name: string;
})[] = [
    {
        name: 'completes a 2-of-3 mixed tally',
        participantCount: 3,
        votes: [1n, 2n, 3n],
        decryptionParticipantIndices: [1, 3],
        expectedQual: [1, 2, 3],
    },
    {
        name: 'completes a 3-of-4 even-participant flow',
        participantCount: 4,
        votes: [1n, 2n, 3n, 1n],
        decryptionParticipantIndices: [1, 3, 4],
        expectedQual: [1, 2, 3, 4],
    },
    {
        name: 'completes a 3-of-5 majority flow',
        participantCount: 5,
        votes: [3n, 2n, 1n, 3n, 2n],
        decryptionParticipantIndices: [1, 3, 5],
        expectedQual: [1, 2, 3, 4, 5],
    },
    {
        name: 'completes a 2-of-3 flow after one dealer complaint',
        participantCount: 3,
        votes: [3n, 1n, 2n],
        complaints: [
            {
                dealerIndex: 1,
                recipientIndex: 2,
                envelopeTamper: 'ciphertext',
            },
        ],
        decryptionParticipantIndices: [2, 3],
        expectedQual: [2, 3],
    },
    {
        name: 'completes a 3-of-4 flow after one dealer complaint',
        participantCount: 4,
        votes: [1n, 2n, 3n, 1n],
        complaints: [
            {
                dealerIndex: 1,
                recipientIndex: 2,
                envelopeTamper: 'iv',
            },
        ],
        decryptionParticipantIndices: [2, 3, 4],
        expectedQual: [2, 3, 4],
    },
    {
        name: 'completes a 2-of-3 flow after one resolved complaint',
        participantCount: 3,
        votes: [2n, 2n, 2n],
        complaints: [
            {
                dealerIndex: 1,
                recipientIndex: 2,
                resolutionOutcome: 'complainant-fault',
            },
        ],
        decryptionParticipantIndices: [1, 2],
        expectedQual: [1, 2, 3],
    },
    {
        name: 'completes a 3-of-4 flow when one dealer misses encrypted-share rows',
        participantCount: 4,
        votes: [3n, 2n, 1n, 3n],
        missingEncryptedShareDealerIndices: [4],
        decryptionParticipantIndices: [1, 2, 3],
        expectedQual: [1, 2, 3],
    },
    {
        name: 'completes a 3-of-4 flow when one dealer misses Pedersen commitments',
        participantCount: 4,
        votes: [1n, 3n, 2n, 1n],
        missingPedersenCommitmentParticipantIndices: [4],
        decryptionParticipantIndices: [1, 2, 3],
        expectedQual: [1, 2, 3],
    },
    {
        name: 'completes a 3-of-4 flow when one dealer misses Feldman commitments',
        participantCount: 4,
        votes: [2n, 3n, 1n, 2n],
        missingFeldmanCommitmentParticipantIndices: [4],
        decryptionParticipantIndices: [1, 2, 3],
        expectedQual: [1, 2, 3],
    },
    {
        name: 'completes a 3-of-4 flow with threshold-only checkpoints and confirmations',
        participantCount: 4,
        votes: [2n, 1n, 3n, 2n],
        includeKeyDerivationConfirmations: true,
        missingKeyDerivationConfirmationParticipantIndices: [4],
        missingPhaseCheckpointSignerIndices: {
            0: [4],
            1: [4],
            2: [4],
            3: [4],
        },
        decryptionParticipantIndices: [1, 2, 3],
        expectedCheckpointPhases: [0, 1, 2, 3],
        expectedConfirmationCount: 3,
        expectedQual: [1, 2, 3, 4],
    },
];

describe('parameterized completed voting flows', () => {
    for (const scenario of completedScenarios) {
        it(
            scenario.name,
            {
                timeout: scenarioTimeoutMs,
            },
            async () => {
                const result = await runVotingFlowScenario(scenario);

                expect(result.finalState.phase).toBe('completed');
                expect(result.finalState.qual).toEqual(scenario.expectedQual);

                if (result.finalState.phase !== 'completed') {
                    throw new Error('Expected a completed voting-flow result');
                }
                const completedResult = result as CompletedVotingFlowResult;

                expect(completedResult.recovered).toBe(
                    scenario.votes.reduce((sum, vote) => sum + vote, 0n),
                );
                expect(completedResult.recoveredWithAllShares).toBe(
                    completedResult.recovered,
                );
                expect(completedResult.aggregate).not.toEqual(
                    completedResult.mismatchedAggregate,
                );
                expect(completedResult.ballots).toHaveLength(
                    scenario.participantCount,
                );
                expect(completedResult.thresholdShareArtifacts).toHaveLength(
                    scenario.decryptionParticipantIndices?.length ??
                        completedResult.finalState.config.threshold,
                );
                expect(completedResult.finalShares).toHaveLength(
                    scenario.expectedQual.length,
                );
                expect(
                    completedResult.transcriptDerivedVerificationKeys,
                ).toHaveLength(scenario.expectedQual.length);
                expect(completedResult.dkgPhaseCheckpoints).toBeDefined();
                expect(completedResult.sessionFingerprint).toMatch(
                    /^[0-9A-F]{4}(?:-[0-9A-F]{4}){7}$/,
                );
                expect(completedResult.complaintResolutions).toHaveLength(
                    scenario.complaints?.length ?? 0,
                );
                expect(
                    completedResult.complaintResolutions.map(
                        (resolution) => resolution.fault,
                    ),
                ).toEqual(
                    (scenario.complaints ?? []).map((complaint) =>
                        complaint.resolutionOutcome === 'complainant-fault'
                            ? 'complainant'
                            : 'dealer',
                    ),
                );

                const checkpointPhases = [
                    ...new Set(
                        (completedResult.dkgPhaseCheckpoints ?? []).map(
                            (checkpoint) => checkpoint.payload.checkpointPhase,
                        ),
                    ),
                ].sort((left, right) => left - right);
                expect(checkpointPhases).toEqual(
                    scenario.expectedCheckpointPhases ?? [0, 1, 2, 3],
                );

                if (scenario.expectedConfirmationCount !== undefined) {
                    expect(
                        completedResult.dkgTranscript.filter(
                            (entry) =>
                                entry.payload.messageType ===
                                'key-derivation-confirmation',
                        ),
                    ).toHaveLength(scenario.expectedConfirmationCount);
                }
            },
        );
    }
});
