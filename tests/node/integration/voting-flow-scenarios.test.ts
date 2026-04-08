import { describe, expect, it } from 'vitest';

import {
    type CompletedVotingFlowResult,
    runVotingFlowScenario,
    type VotingFlowScenario,
} from './voting-flow-harness.js';

const scenarioTimeoutMs = 20_000;

const completedScenarios: readonly (VotingFlowScenario & {
    readonly expectedQual: readonly number[];
    readonly name: string;
})[] = [
    {
        name: 'completes a 2-of-3 mixed tally',
        participantCount: 3,
        votes: [7n, 4n, 9n],
        decryptionParticipantIndices: [1, 3],
        expectedQual: [1, 2, 3],
    },
    {
        name: 'completes a 2-of-3 unanimous maximum tally',
        participantCount: 3,
        votes: [10n, 10n, 10n],
        decryptionParticipantIndices: [1, 2],
        expectedQual: [1, 2, 3],
    },
    {
        name: 'completes a 2-of-3 partial recovery flow',
        participantCount: 3,
        votes: [2n, 5n, 8n],
        decryptionParticipantIndices: [1, 2],
        expectedQual: [1, 2, 3],
    },
    {
        name: 'completes a 2-of-4 even-participant flow',
        participantCount: 4,
        votes: [1n, 3n, 5n, 7n],
        decryptionParticipantIndices: [1, 4],
        expectedQual: [1, 2, 3, 4],
    },
    {
        name: 'completes a 3-of-5 majority flow',
        participantCount: 5,
        votes: [10n, 9n, 8n, 7n, 6n],
        decryptionParticipantIndices: [1, 3, 5],
        expectedQual: [1, 2, 3, 4, 5],
    },
    {
        name: 'completes a 3-of-5 abstention-aware flow',
        participantCount: 5,
        votes: [0n, 10n, 0n, 10n, 10n],
        allowAbstention: true,
        decryptionParticipantIndices: [2, 4, 5],
        expectedQual: [1, 2, 3, 4, 5],
    },
    {
        name: 'completes a 2-of-3 flow after one dealer complaint',
        participantCount: 3,
        votes: [6n, 1n, 5n],
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
        name: 'completes a 2-of-4 flow after one dealer complaint',
        participantCount: 4,
        votes: [3n, 6n, 9n, 1n],
        complaints: [
            {
                dealerIndex: 1,
                recipientIndex: 2,
                envelopeTamper: 'iv',
            },
        ],
        decryptionParticipantIndices: [2, 4],
        expectedQual: [2, 3, 4],
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
                expect(completedResult.sessionFingerprint).toMatch(
                    /^[0-9A-F]{4}(?:-[0-9A-F]{4}){7}$/,
                );
                expect(
                    completedResult.complaintResolutions.every(
                        (resolution) => resolution.fault === 'dealer',
                    ),
                ).toBe(true);
            },
        );
    }
});
