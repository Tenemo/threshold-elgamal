import { beforeAll, describe, expect, it } from 'vitest';

import { runVotingFlowScenario } from '../../../tools/internal/voting-flow-harness';

import {
    createBallotSubmissionPayload,
    createDisjunctiveProof,
    createDecryptionSharePayload,
    createTallyPublicationPayload,
    encryptAdditiveWithRandomness,
    RISTRETTO_GROUP,
    SHIPPED_PROTOCOL_VERSION,
    signProtocolPayload,
    tryVerifyElectionCeremony,
    verifyElectionCeremony,
    type ProofContext,
    type SignedPayload,
} from '#root';

const fixtureTimeoutMs = 240_000;
const defaultScoreRange = { min: 1, max: 10 } as const;

type VotingFlowFixture = Awaited<ReturnType<typeof runVotingFlowScenario>>;
type VerifiedCeremonyProjection = {
    readonly countedParticipantIndices: readonly number[];
    readonly decryptionParticipantSets: readonly (readonly number[])[];
    readonly excludedParticipantIndices: readonly number[];
    readonly qualifiedParticipantIndices: readonly number[];
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
        ballotClosePayloads: readonly VotingFlowFixture['ballotClosePayload'][];
        ballotPayloads: VotingFlowFixture['ballotPayloads'];
        decryptionSharePayloads: VotingFlowFixture['decryptionSharePayloads'];
        dkgTranscript: VotingFlowFixture['dkgTranscript'];
        tallyPublications: VotingFlowFixture['tallyPublications'];
    }> = {},
): Parameters<typeof verifyElectionCeremony>[0] => ({
    manifest: fixture.manifest,
    sessionId: fixture.sessionId,
    dkgTranscript: overrides.dkgTranscript ?? fixture.dkgTranscript,
    ballotPayloads: overrides.ballotPayloads ?? fixture.ballotPayloads,
    ballotClosePayloads: overrides.ballotClosePayloads ?? [
        fixture.ballotClosePayload,
    ],
    decryptionSharePayloads:
        overrides.decryptionSharePayloads ?? fixture.decryptionSharePayloads,
    tallyPublications: overrides.tallyPublications ?? fixture.tallyPublications,
});

const projectVerifiedCeremony = (
    verified: Awaited<ReturnType<typeof verifyElectionCeremony>>,
): VerifiedCeremonyProjection => ({
    countedParticipantIndices: verified.countedParticipantIndices,
    excludedParticipantIndices: verified.excludedParticipantIndices,
    qualifiedParticipantIndices: verified.qualifiedParticipantIndices,
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
    resultPromise: ReturnType<typeof tryVerifyElectionCeremony>,
    expected: {
        readonly code:
            | 'MANIFEST_INVALID'
            | 'BOARD_INVALID'
            | 'DKG_INVALID'
            | 'SIGNATURE_INVALID'
            | 'BALLOT_INVALID'
            | 'DECRYPTION_INVALID'
            | 'TALLY_INVALID';
        readonly reasonFragment: string;
        readonly stage:
            | 'manifest'
            | 'board'
            | 'dkg'
            | 'signatures'
            | 'ballots'
            | 'decryption'
            | 'tally';
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
                scoreRange: defaultScoreRange,
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
                scoreRange: defaultScoreRange,
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
        'verifies a complaint-path ceremony and reduces the qualified participant set after an accepted dealer complaint',
        () => {
            expect(complaintFixture.qualifiedParticipantIndices).toEqual([
                1, 2, 3,
            ]);
            expect(
                complaintFixture.verified.qualifiedParticipantIndices,
            ).toEqual([1, 2, 3]);
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
                    verifyElectionCeremony(verificationInput(fullFixture)),
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
            const verified = await verifyElectionCeremony(
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
                tryVerifyElectionCeremony(
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
            tryVerifyElectionCeremony(
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
            tryVerifyElectionCeremony(
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

    it('rejects ceremonies with an invalid manifest before board replay begins', async () => {
        await expectFailure(
            tryVerifyElectionCeremony({
                ...verificationInput(fullFixture),
                manifest: {
                    ...fullFixture.manifest,
                    optionList: ['One', 'One', 'Three'],
                },
            }),
            {
                code: 'MANIFEST_INVALID',
                stage: 'manifest',
                reasonFragment: 'Duplicate option "One" is not allowed',
            },
        );
    });

    it('rejects signed ballot payloads whose signature bytes no longer match the registered auth key', async () => {
        const original = findBallotPayload(fullFixture, 1, 1);

        await expectFailure(
            tryVerifyElectionCeremony(
                verificationInput(fullFixture, {
                    ballotPayloads: replaceSignedPayload(
                        fullFixture.ballotPayloads,
                        (payload) =>
                            payload.payload.participantIndex === 1 &&
                            payload.payload.optionIndex === 1,
                        {
                            ...original,
                            signature: corruptHexTailByte(original.signature),
                        },
                    ),
                }),
            ),
            {
                code: 'SIGNATURE_INVALID',
                stage: 'signatures',
                reasonFragment:
                    'Payload signature failed verification for participant 1 (ballot-submission)',
            },
        );
    });

    it('rejects published payloads that claim an unregistered participant index after DKG succeeds', async () => {
        const original = findBallotPayload(fullFixture, 1, 1);
        const forgedUnregisteredBallot = await signProtocolPayload(
            fullFixture.participants[0].auth.privateKey,
            {
                ...original.payload,
                participantIndex: 5,
            },
        );

        await expectFailure(
            tryVerifyElectionCeremony(
                verificationInput(fullFixture, {
                    ballotPayloads: replaceSignedPayload(
                        fullFixture.ballotPayloads,
                        (payload) =>
                            payload.payload.participantIndex === 1 &&
                            payload.payload.optionIndex === 1,
                        forgedUnregisteredBallot,
                    ),
                }),
            ),
            {
                code: 'SIGNATURE_INVALID',
                stage: 'signatures',
                reasonFragment: 'Missing registration for participant 5',
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
            tryVerifyElectionCeremony(
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

    it('rejects ballot payloads proven against a different score domain than the manifest declares', async () => {
        const randomness = 41n;
        const ciphertext = encryptAdditiveWithRandomness(
            0n,
            fullFixture.verified.dkg.jointPublicKey,
            randomness,
            10n,
        );
        const proofContext: ProofContext = {
            protocolVersion: SHIPPED_PROTOCOL_VERSION,
            suiteId: RISTRETTO_GROUP.name,
            manifestHash: fullFixture.manifestHash,
            sessionId: fullFixture.sessionId,
            label: 'ballot-range-proof',
            voterIndex: 1,
            optionIndex: 1,
        };
        const forgedBallot = await createBallotSubmissionPayload(
            fullFixture.participants[0].auth.privateKey,
            {
                ...findBallotPayload(fullFixture, 1, 1).payload,
                ciphertext,
                proof: await createDisjunctiveProof(
                    0n,
                    randomness,
                    ciphertext,
                    fullFixture.verified.dkg.jointPublicKey,
                    Array.from({ length: 10 }, (_value, index) =>
                        BigInt(index),
                    ),
                    RISTRETTO_GROUP,
                    proofContext,
                ),
            },
        );

        await expectFailure(
            tryVerifyElectionCeremony(
                verificationInput(fullFixture, {
                    ballotPayloads: replaceSignedPayload(
                        fullFixture.ballotPayloads,
                        (payload) =>
                            payload.payload.participantIndex === 1 &&
                            payload.payload.optionIndex === 1,
                        forgedBallot,
                    ),
                }),
            ),
            {
                code: 'BALLOT_INVALID',
                stage: 'ballots',
                reasonFragment:
                    'Ballot proof failed verification for voter 1 option 1',
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
            tryVerifyElectionCeremony(
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

    it('rejects ceremonies when one option is missing a threshold-sized decryption subset', async () => {
        await expectFailure(
            tryVerifyElectionCeremony(
                verificationInput(fullFixture, {
                    decryptionSharePayloads:
                        fullFixture.decryptionSharePayloads.filter(
                            (payload) =>
                                !(
                                    payload.payload.optionIndex === 1 &&
                                    payload.payload.participantIndex === 2
                                ),
                        ),
                }),
            ),
            {
                code: 'DECRYPTION_INVALID',
                stage: 'decryption',
                reasonFragment:
                    'At least 2 decryption shares are required for option 1',
            },
        );
    });

    it('rejects complaint-path ceremonies when a disqualified dealer still posts a decryption share', async () => {
        const original = findDecryptionSharePayload(complaintFixture, 1, 1);
        const disqualifiedShare = await createDecryptionSharePayload(
            complaintFixture.participants[3].auth.privateKey,
            {
                ...original.payload,
                participantIndex: 4,
            },
        );

        await expectFailure(
            tryVerifyElectionCeremony(
                verificationInput(complaintFixture, {
                    decryptionSharePayloads: replaceSignedPayload(
                        complaintFixture.decryptionSharePayloads,
                        (payload) =>
                            payload.payload.participantIndex === 1 &&
                            payload.payload.optionIndex === 1,
                        disqualifiedShare,
                    ),
                }),
            ),
            {
                code: 'DECRYPTION_INVALID',
                stage: 'decryption',
                reasonFragment:
                    'Decryption share came from non-qualified participant 4',
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
            tryVerifyElectionCeremony(
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

    it('rejects ceremonies when one tally publication is missing after successful decryption-share verification', async () => {
        await expectFailure(
            tryVerifyElectionCeremony(
                verificationInput(fullFixture, {
                    tallyPublications: fullFixture.tallyPublications.slice(1),
                }),
            ),
            {
                code: 'TALLY_INVALID',
                stage: 'tally',
                reasonFragment:
                    'Expected 3 tally-publication payloads, received 2',
            },
        );
    });

    it('rejects conflicting tally publications for one canonical board slot as board equivocation', async () => {
        const duplicateOptionOnePublication =
            await createTallyPublicationPayload(
                fullFixture.participants[0].auth.privateKey,
                {
                    ...fullFixture.tallyPublications[1].payload,
                    optionIndex: 1,
                },
            );

        await expectFailure(
            tryVerifyElectionCeremony(
                verificationInput(fullFixture, {
                    tallyPublications: [
                        fullFixture.tallyPublications[0],
                        duplicateOptionOnePublication,
                        fullFixture.tallyPublications[2],
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
                tryVerifyElectionCeremony(
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
