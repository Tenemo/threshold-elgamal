import { runVotingFlowScenario } from './voting-flow-harness.mjs';

const assert = (condition, message) => {
    if (!condition) {
        throw new Error(message);
    }
};

const result = await runVotingFlowScenario({
    participantCount: 3,
    optionList: ['Option A', 'Option B'],
    participantVotes: [
        [4n, 1n],
        [7n, 9n],
        [9n, 3n],
    ],
    sessionNonce: 'packed-smoke-nonce',
    timestamp: '2026-04-11T12:00:00Z',
});

assert(
    result.participants.length === 3,
    'Packed smoke scenario produced the wrong participant count',
);
assert(
    result.threshold === 2,
    'Packed smoke scenario derived the wrong threshold',
);
assert(
    result.verified.dkg.participantCount === 3,
    'Packed smoke verifier derived the wrong participant count',
);
assert(
    result.verified.dkg.threshold === 2,
    'Packed smoke verifier derived the wrong threshold',
);
assert(
    result.expectedTallies[0] === 20n &&
        result.verified.perOptionTallies[0]?.tally === 20n,
    'Packed smoke verifier derived the wrong tally for option 1',
);
assert(
    result.expectedTallies[1] === 13n &&
        result.verified.perOptionTallies[1]?.tally === 13n,
    'Packed smoke verifier derived the wrong tally for option 2',
);
assert(
    result.countedParticipantIndices.join(',') === '1,2,3' &&
        result.verified.countedParticipantIndices.join(',') === '1,2,3',
    'Packed smoke verifier counted the wrong participants',
);

console.log('Packed package honest-majority voting smoke test passed.');
