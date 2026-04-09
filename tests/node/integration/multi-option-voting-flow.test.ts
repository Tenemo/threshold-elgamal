import { describe, expect, it } from 'vitest';

import {
    runVotingFlowScenario,
    type CompletedVotingFlowResult,
    type VotingFlowResult,
} from './voting-flow-harness.js';

const expectCompleted = (
    result: VotingFlowResult,
    label: string,
): CompletedVotingFlowResult => {
    if (result.finalState.phase !== 'completed') {
        throw new Error(label);
    }

    return result as CompletedVotingFlowResult;
};

describe('multi-option voting flows', () => {
    it(
        'completes a multi-option 3-of-5 flow with one tally per option',
        {
            timeout: 90_000,
        },
        async () => {
            const result = expectCompleted(
                await runVotingFlowScenario({
                    participantCount: 5,
                    scoreDomainMax: 3,
                    optionList: ['Alpha', 'Beta', 'Gamma'],
                    votes: [3n, 2n, 1n, 3n, 2n],
                    votesByOption: [
                        [3n, 2n, 1n, 3n, 2n],
                        [1n, 3n, 2n, 1n, 2n],
                        [2n, 1n, 3n, 2n, 1n],
                    ],
                    decryptionParticipantIndices: [1, 3, 5],
                }),
                'Expected the multi-option scenario to complete',
            );

            expect(result.finalState.config.threshold).toBe(3);
            expect(result.ballots).toHaveLength(15);
            expect(result.optionResults).toBeDefined();
            expect(result.tallyPublications).toBeDefined();

            const optionResults = result.optionResults ?? [];
            expect(optionResults.map((entry) => entry.optionIndex)).toEqual([
                1, 2, 3,
            ]);
            expect(optionResults.map((entry) => entry.ballots.length)).toEqual([
                5, 5, 5,
            ]);
            expect(optionResults.map((entry) => entry.expectedTally)).toEqual([
                11n,
                9n,
                9n,
            ]);
            expect(optionResults.map((entry) => entry.recovered)).toEqual([
                11n,
                9n,
                9n,
            ]);
            expect(
                optionResults.map(
                    (entry) => Number(entry.recovered) / entry.ballots.length,
                ),
            ).toEqual([2.2, 1.8, 1.8]);
            expect(
                optionResults.every(
                    (entry) => entry.thresholdShareArtifacts.length === 3,
                ),
            ).toBe(true);
            expect(result.tallyPublications).toHaveLength(3);
        },
    );
});
