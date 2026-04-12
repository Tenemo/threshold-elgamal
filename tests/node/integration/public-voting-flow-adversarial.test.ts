import { beforeAll, describe, expect, it } from 'vitest';

import { runVotingFlowScenario } from '../../../tools/internal/voting-flow-harness.js';

import {
    createBallotSubmissionPayload,
    createDecryptionSharePayload,
    createTallyPublicationPayload,
    verifyElectionCeremonyDetailed,
    verifyElectionCeremonyDetailedResult,
    type SignedPayload,
} from '#root';

const fixtureTimeoutMs = 240_000;

type VotingFlowFixture = Awaited<ReturnType<typeof runVotingFlowScenario>>;
type VerifiedCeremonyProjection = {
    readonly countedParticipantIndices: readonly number[];
    readonly decryptionParticipantSets: readonly (readonly number[])[];
    readonly excludedParticipantIndices: readonly number[];
    readonly qual: readonly number[];
    readonly tallies: readonly bigint[];
    readonly transcriptHashes: readonly string[];
};

const corruptHexTailByte = (value: string): string => {
    const lastByte = Number.parseInt(value.slice(-2), 16);
    const corruptedByte = (lastByte ^ 0x01).toString(16).padStart(2, '0');

    return `${value.slice(0, -2)}${corruptedByte}`;
};

const verificationInput = (
    fixture: VotingFlowFixture,
    overrides: Partial<{
        ballotClosePayload: VotingFlowFixture['ballotClosePayload'];
        ballotPayloads: VotingFlowFixture['ballotPayloads'];
        decryptionSharePayloads: VotingFlowFixture['decryptionSharePayloads'];
        dkgTranscript: VotingFlowFixture['dkgTranscript'];
        tallyPublications: VotingFlowFixture['tallyPublications'];
    }> = {},
): Parameters<typeof verifyElectionCeremonyDetailed>[0] => ({
    manifest: fixture.manifest,
    sessionId: fixture.sessionId,
    dkgTranscript: overrides.dkgTranscript ?? fixture.dkgTranscript,
    ballotPayloads: overrides.ballotPayloads ?? fixture.ballotPayloads,
    ballotClosePayload:
        overrides.ballotClosePayload ?? fixture.ballotClosePayload,
    decryptionSharePayloads:
        overrides.decryptionSharePayloads ?? fixture.decryptionSharePayloads,
    tallyPublications: overrides.tallyPublications ?? fixture.tallyPublications,
});

const projectVerifiedCeremony = (
    verified: Awaited<ReturnType<typeof verifyElectionCeremonyDetailed>>,
): VerifiedCeremonyProjection => ({
    countedParticipantIndices: verified.countedParticipantIndices,
    excludedParticipantIndices: verified.excludedParticipantIndices,
    qual: verified.qual,
    transcriptHashes: verified.options.map(
        (option) => option.ballots.aggregate.transcriptHash,
    ),
    decryptionParticipantSets: verified.options.map((option) =>
        option.decryptionShares.map((entry) => entry.share.index),
    ),
    tallies: verified.perOptionTallies.map((option) => option.tally),
});

const findBallotPayload = (
    fixture: VotingFlowFixture,
    participantIndex: number,
    optionIndex: number,
): VotingFlowFixture['ballotPayloads'][number] => {
    const payload = fixture.ballotPayloads.find(
        (entry) =>
            entry.payload.participantIndex === participantIndex &&
            entry.payload.optionIndex === optionIndex,
    );

    if (payload === undefined) {
        throw new Error(
            `Missing ballot payload for participant ${participantIndex} option ${optionIndex}`,
        );
    }

    return payload;
};

const findDecryptionSharePayload = (
    fixture: VotingFlowFixture,
    participantIndex: number,
    optionIndex: number,
): VotingFlowFixture['decryptionSharePayloads'][number] => {
    const payload = fixture.decryptionSharePayloads.find(
        (entry) =>
            entry.payload.participantIndex === participantIndex &&
            entry.payload.optionIndex === optionIndex,
    );

    if (payload === undefined) {
        throw new Error(
            `Missing decryption share for participant ${participantIndex} option ${optionIndex}`,
        );
    }

    return payload;
};

const replaceSignedPayload = <TPayload extends SignedPayload>(
    payloads: readonly TPayload[],
    matcher: (payload: TPayload) => boolean,
    replacement: TPayload,
): readonly TPayload[] =>
    payloads.map((payload) => (matcher(payload) ? replacement : payload));

const expectFailure = async (
    resultPromise: ReturnType<typeof verifyElectionCeremonyDetailedResult>,
    expected: {
        readonly code:
            | 'BOARD_INVALID'
            | 'DKG_INVALID'
            | 'BALLOT_INVALID'
            | 'DECRYPTION_INVALID'
            | 'TALLY_INVALID';
        readonly reasonFragment: string;
        readonly stage: 'board' | 'dkg' | 'ballots' | 'decryption' | 'tally';
    },
): Promise<void> => {
    const result = await resultPromise;

    expect(result.ok).toBe(false);
    if (result.ok) {
        return;
    }

    expect(result.error.code).toBe(expected.code);
    expect(result.error.stage).toBe(expected.stage);
    expect(result.error.reason).toContain(expected.reasonFragment);
};

describe('honest-majority voting flow adversarial coverage', () => {
    let fullFixture: VotingFlowFixture;
    let complaintFixture: VotingFlowFixture;

    beforeAll(async () => {
        [fullFixture, complaintFixture] = await Promise.all([
            runVotingFlowScenario({
                participantCount: 4,
                optionList: ['One', 'Two', 'Three'],
                participantVotes: [
                    [1n, 2n, 3n],
                    [4n, 5n, 6n],
                    [7n, 8n, 9n],
                    [10n, 1n, 2n],
                ],
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
                dkgComplaint: {
                    dealerIndex: 4,
                    complainantIndex: 2,
                    outcome: 'accepted',
                    reason: 'aes-gcm-failure',
                },
            }),
        ]);
    }, fixtureTimeoutMs);

    it(
        'verifies a complaint-path ceremony and reduces qual after an accepted dealer complaint',
        () => {
            expect(complaintFixture.qualifiedParticipantIndices).toEqual([
                1, 2, 3,
            ]);
            expect(complaintFixture.verified.qual).toEqual([1, 2, 3]);
            expect(complaintFixture.verified.dkg.acceptedComplaints).toEqual([
                expect.objectContaining({
                    participantIndex: 2,
                    dealerIndex: 4,
                    envelopeId: 'env-4-2',
                    reason: 'aes-gcm-failure',
                }),
            ]);
            expect(
                complaintFixture.verified.options.map((option) =>
                    option.decryptionShares.map((entry) => entry.share.index),
                ),
            ).toEqual([
                [1, 2],
                [1, 2],
                [1, 2],
            ]);
            expect(
                complaintFixture.verified.perOptionTallies.map(
                    (option) => option.tally,
                ),
            ).toEqual(complaintFixture.expectedTallies);
        },
        fixtureTimeoutMs,
    );

    it(
        'derives identical outputs when multiple verifiers replay the same board independently',
        async () => {
            const replays = await Promise.all(
                Array.from({ length: 3 }, () =>
                    verifyElectionCeremonyDetailed(
                        verificationInput(fullFixture),
                    ),
                ),
            );
            const baseline = projectVerifiedCeremony(fullFixture.verified);

            replays.forEach((replay) => {
                expect(projectVerifiedCeremony(replay)).toEqual(baseline);
            });
        },
        fixtureTimeoutMs,
    );

    it(
        'accepts exact signed retransmissions and collapses them to one canonical ballot slot',
        async () => {
            const duplicateBallot = findBallotPayload(fullFixture, 1, 1);
            const verified = await verifyElectionCeremonyDetailed(
                verificationInput(fullFixture, {
                    ballotPayloads: [
                        ...fullFixture.ballotPayloads,
                        duplicateBallot,
                    ],
                }),
            );

            expect(verified.perOptionTallies).toEqual(
                fullFixture.verified.perOptionTallies,
            );
            expect(verified.boardAudit.ballots.acceptedPayloads).toHaveLength(
                fullFixture.ballotPayloads.length,
            );
            expect(verified.boardAudit.ballots.slotAudit).toContainEqual(
                expect.objectContaining({
                    occurrences: 2,
                    status: 'idempotent-retransmission',
                }),
            );
        },
        fixtureTimeoutMs,
    );

    it(
        'rejects same-payload retransmissions whose signature bytes differ',
        async () => {
            const original = findBallotPayload(fullFixture, 1, 1);

            await expectFailure(
                verifyElectionCeremonyDetailedResult(
                    verificationInput(fullFixture, {
                        ballotPayloads: [
                            ...fullFixture.ballotPayloads,
                            {
                                ...original,
                                signature: corruptHexTailByte(
                                    original.signature,
                                ),
                            },
                        ],
                    }),
                ),
                {
                    code: 'BOARD_INVALID',
                    stage: 'board',
                    reasonFragment:
                        'Detected non-identical retransmission for canonical slot',
                },
            );
        },
        fixtureTimeoutMs,
    );

    it('rejects ballot equivocation on one canonical board slot', async () => {
        const original = findBallotPayload(fullFixture, 1, 1);
        const equivocated = await createBallotSubmissionPayload(
            fullFixture.participants[0].auth.privateKey,
            {
                ...original.payload,
                proof: {
                    branches: original.payload.proof.branches.map(
                        (branch, branchIndex) =>
                            branchIndex === 0
                                ? {
                                      ...branch,
                                      challenge: corruptHexTailByte(
                                          branch.challenge,
                                      ),
                                  }
                                : branch,
                    ),
                },
            },
        );

        await expectFailure(
            verifyElectionCeremonyDetailedResult(
                verificationInput(fullFixture, {
                    ballotPayloads: [
                        ...fullFixture.ballotPayloads,
                        equivocated,
                    ],
                }),
            ),
            {
                code: 'BOARD_INVALID',
                stage: 'board',
                reasonFragment: 'Detected equivocation for canonical slot',
            },
        );
    });

    it('rejects ceremonies with a missing registration payload', async () => {
        await expectFailure(
            verifyElectionCeremonyDetailedResult(
                verificationInput(fullFixture, {
                    dkgTranscript: fullFixture.dkgTranscript.filter(
                        (entry) =>
                            entry.payload.messageType !== 'registration' ||
                            entry.payload.participantIndex !== 4,
                    ),
                }),
            ),
            {
                code: 'DKG_INVALID',
                stage: 'dkg',
                reasonFragment: 'Missing registration for participant 4',
            },
        );
    });

    it('rejects ballot payloads with a replayed proof from another option', async () => {
        const optionOneBallot = findBallotPayload(fullFixture, 1, 1);
        const forgedOptionTwoBallot = await createBallotSubmissionPayload(
            fullFixture.participants[0].auth.privateKey,
            {
                ...findBallotPayload(fullFixture, 1, 2).payload,
                ciphertext: optionOneBallot.payload.ciphertext,
                proof: optionOneBallot.payload.proof,
            },
        );

        await expectFailure(
            verifyElectionCeremonyDetailedResult(
                verificationInput(fullFixture, {
                    ballotPayloads: replaceSignedPayload(
                        fullFixture.ballotPayloads,
                        (payload) =>
                            payload.payload.participantIndex === 1 &&
                            payload.payload.optionIndex === 2,
                        forgedOptionTwoBallot,
                    ),
                }),
            ),
            {
                code: 'BALLOT_INVALID',
                stage: 'ballots',
                reasonFragment:
                    'Ballot proof failed verification for voter 1 option 2',
            },
        );
    });

    it('rejects decryption shares with a replayed proof from another option', async () => {
        const optionOneShare = findDecryptionSharePayload(fullFixture, 1, 1);
        const forgedOptionTwoShare = await createDecryptionSharePayload(
            fullFixture.participants[0].auth.privateKey,
            {
                ...findDecryptionSharePayload(fullFixture, 1, 2).payload,
                proof: optionOneShare.payload.proof,
            },
        );

        await expectFailure(
            verifyElectionCeremonyDetailedResult(
                verificationInput(fullFixture, {
                    decryptionSharePayloads: replaceSignedPayload(
                        fullFixture.decryptionSharePayloads,
                        (payload) =>
                            payload.payload.participantIndex === 1 &&
                            payload.payload.optionIndex === 2,
                        forgedOptionTwoShare,
                    ),
                }),
            ),
            {
                code: 'DECRYPTION_INVALID',
                stage: 'decryption',
                reasonFragment:
                    'Decryption-share proof failed verification for participant 1 and option 2',
            },
        );
    });

    it('rejects tally publications whose decryption participant set does not match the supplied shares', async () => {
        const forgedTallyPublication = await createTallyPublicationPayload(
            fullFixture.participants[0].auth.privateKey,
            {
                ...fullFixture.tallyPublications[0].payload,
                decryptionParticipantIndices: [1, 3],
            },
        );

        await expectFailure(
            verifyElectionCeremonyDetailedResult(
                verificationInput(fullFixture, {
                    tallyPublications: [
                        forgedTallyPublication,
                        ...fullFixture.tallyPublications.slice(1),
                    ],
                }),
            ),
            {
                code: 'TALLY_INVALID',
                stage: 'tally',
                reasonFragment:
                    'Tally publication decryption participant set does not match the supplied decryption shares for option 1',
            },
        );
    });

    it.each([
        {
            name: 'session',
            mutate: async () =>
                createBallotSubmissionPayload(
                    fullFixture.participants[0].auth.privateKey,
                    {
                        ...findBallotPayload(fullFixture, 1, 1).payload,
                        sessionId: 'session-replay',
                    },
                ),
            reasonFragment:
                'Ballot submission payload session does not match the verification input',
        },
        {
            name: 'manifest',
            mutate: async () =>
                createBallotSubmissionPayload(
                    fullFixture.participants[0].auth.privateKey,
                    {
                        ...findBallotPayload(fullFixture, 1, 1).payload,
                        manifestHash: 'aa'.repeat(32),
                    },
                ),
            reasonFragment:
                'Ballot submission payload manifest hash does not match the verification input',
        },
        {
            name: 'voter',
            mutate: async () =>
                createBallotSubmissionPayload(
                    fullFixture.participants[1].auth.privateKey,
                    {
                        ...findBallotPayload(fullFixture, 2, 1).payload,
                        ciphertext: findBallotPayload(fullFixture, 1, 1).payload
                            .ciphertext,
                        proof: findBallotPayload(fullFixture, 1, 1).payload
                            .proof,
                    },
                ),
            reasonFragment:
                'Ballot proof failed verification for voter 2 option 1',
        },
        {
            name: 'option',
            mutate: async () =>
                createBallotSubmissionPayload(
                    fullFixture.participants[0].auth.privateKey,
                    {
                        ...findBallotPayload(fullFixture, 1, 2).payload,
                        ciphertext: findBallotPayload(fullFixture, 1, 1).payload
                            .ciphertext,
                        proof: findBallotPayload(fullFixture, 1, 1).payload
                            .proof,
                    },
                ),
            reasonFragment:
                'Ballot proof failed verification for voter 1 option 2',
        },
    ] as const)(
        'rejects ballot replay attempts across $name bindings',
        async (entry) => {
            const replayedBallot = await entry.mutate();
            const matcher = (
                payload: VotingFlowFixture['ballotPayloads'][number],
            ): boolean => {
                switch (entry.name) {
                    case 'session':
                    case 'manifest':
                        return (
                            payload.payload.participantIndex === 1 &&
                            payload.payload.optionIndex === 1
                        );
                    case 'voter':
                        return (
                            payload.payload.participantIndex === 2 &&
                            payload.payload.optionIndex === 1
                        );
                    case 'option':
                        return (
                            payload.payload.participantIndex === 1 &&
                            payload.payload.optionIndex === 2
                        );
                }
            };

            await expectFailure(
                verifyElectionCeremonyDetailedResult(
                    verificationInput(fullFixture, {
                        ballotPayloads: replaceSignedPayload(
                            fullFixture.ballotPayloads,
                            matcher,
                            replayedBallot,
                        ),
                    }),
                ),
                {
                    code: 'BALLOT_INVALID',
                    stage: 'ballots',
                    reasonFragment: entry.reasonFragment,
                },
            );
        },
        fixtureTimeoutMs,
    );
});
