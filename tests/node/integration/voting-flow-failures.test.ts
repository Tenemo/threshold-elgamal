import { describe, expect, it } from 'vitest';

import {
    runVotingFlowScenario,
    type VotingFlowScenario,
} from './voting-flow-harness.js';

const scenarioTimeoutMs = 20_000;

const abortingScenarios: readonly (VotingFlowScenario & {
    readonly expectedQual: readonly number[];
    readonly name: string;
})[] = [
    {
        name: 'aborts a 3-of-3 ceremony after one dealer complaint',
        participantCount: 3,
        threshold: 3,
        votes: [8n, 1n, 1n],
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
        name: 'aborts a 3-of-4 ceremony after two dealer complaints',
        participantCount: 4,
        threshold: 3,
        votes: [4n, 4n, 4n, 4n],
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
});
