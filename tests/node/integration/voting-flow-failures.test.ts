import { describe, expect, it } from 'vitest';

import {
    runVotingFlowScenario,
    type VotingFlowScenario,
} from '../../../dev-support/voting-flow-harness.js';

const scenarioTimeoutMs = 60_000;

const abortingScenarios: readonly (VotingFlowScenario & {
    readonly expectedQual: readonly number[];
    readonly name: string;
})[] = [
    {
        name: 'aborts a 2-of-3 ceremony after two dealer complaints',
        participantCount: 3,
        votes: [3n, 1n, 1n],
        complaints: [
            {
                dealerIndex: 1,
                recipientIndex: 2,
                envelopeTamper: 'ciphertext',
            },
            {
                dealerIndex: 2,
                recipientIndex: 3,
                envelopeTamper: 'iv',
            },
        ],
        expectedQual: [3],
    },
    {
        name: 'aborts a 3-of-3 ceremony after one dealer complaint',
        participantCount: 3,
        threshold: 3,
        votes: [2n, 2n, 1n],
        complaints: [
            {
                dealerIndex: 1,
                recipientIndex: 2,
                envelopeTamper: 'ciphertext',
            },
        ],
        expectedQual: [2, 3],
    },
    {
        name: 'aborts a 3-of-4 ceremony after three dealer complaints',
        participantCount: 4,
        votes: [3n, 3n, 3n, 3n],
        complaints: [
            {
                dealerIndex: 1,
                recipientIndex: 2,
                envelopeTamper: 'ciphertext',
            },
            {
                dealerIndex: 2,
                recipientIndex: 3,
                envelopeTamper: 'ephemeralPublicKey',
            },
            {
                dealerIndex: 3,
                recipientIndex: 4,
                envelopeTamper: 'iv',
            },
        ],
        expectedQual: [3, 4],
    },
];

describe('parameterized aborting voting flows', () => {
    for (const scenario of abortingScenarios) {
        it(
            scenario.name,
            {
                timeout: scenarioTimeoutMs,
            },
            async () => {
                const result = await runVotingFlowScenario(scenario);

                expect(result.finalState.phase).toBe('aborted');
                expect(result.finalState.abortReason).toBe('qual-too-small');
                expect(result.finalState.qual).toEqual(scenario.expectedQual);
                expect(result.ballots).toEqual([]);
                expect(result.complaintResolutions).toHaveLength(
                    scenario.complaints?.length ?? 0,
                );
                expect(
                    result.complaintResolutions.every(
                        (resolution) =>
                            resolution.valid === false &&
                            resolution.fault === 'dealer',
                    ),
                ).toBe(true);
            },
        );
    }

    it('rejects scenarios that define no option vote sets', async () => {
        await expect(
            runVotingFlowScenario({
                participantCount: 3,
                votes: [3n, 2n, 1n],
                votesByOption: [],
            }),
        ).rejects.toThrow('Scenario must define at least one option vote set');
    });
});
