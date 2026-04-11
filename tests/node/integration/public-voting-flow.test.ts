import {
    createDecryptionSharePayload,
    createElectionManifest,
    createTallyPublicationPayload,
    majorityThreshold,
    signProtocolPayload,
    verifyElectionCeremonyDetailed,
} from 'threshold-elgamal';

import { beforeAll, describe, expect, it } from 'vitest';

import { runVotingFlowScenario } from '../../../dev-support/voting-flow-harness.js';

const fixtureTimeoutMs = 240_000;

const allParticipantIndices = (participantCount: number): readonly number[] =>
    Array.from({ length: participantCount }, (_value, offset) => offset + 1);

const positiveScenarios = [
    {
        name: 'verifies a full 10-participant ceremony when all participants vote',
        scenario: {
            participantCount: 10,
            optionCount: 8,
            votingParticipantIndices: allParticipantIndices(10),
            closeParticipantIndices: allParticipantIndices(10),
        },
        expectedExcluded: [],
        expectedAcceptedCount: 10,
    },
    {
        name: 'verifies a 10-participant ceremony when one participant never posts a ballot',
        scenario: {
            participantCount: 10,
            optionCount: 8,
            votingParticipantIndices: allParticipantIndices(9),
            closeParticipantIndices: allParticipantIndices(9),
        },
        expectedExcluded: [],
        expectedAcceptedCount: 9,
    },
    {
        name: 'verifies that organizer cutoff excludes already-posted late ballots in an auditable way',
        scenario: {
            participantCount: 10,
            optionCount: 8,
            votingParticipantIndices: allParticipantIndices(10),
            closeParticipantIndices: allParticipantIndices(8),
        },
        expectedExcluded: [9, 10],
        expectedAcceptedCount: 8,
    },
    {
        name: 'verifies a 10-participant ceremony when the organizer closes at the majority threshold',
        scenario: {
            participantCount: 10,
            optionCount: 8,
            votingParticipantIndices: allParticipantIndices(5),
            closeParticipantIndices: allParticipantIndices(5),
        },
        expectedExcluded: [],
        expectedAcceptedCount: 5,
    },
    {
        name: 'verifies a 3-participant ceremony with multiple options and boundary score values',
        scenario: {
            participantCount: 3,
            optionList: ['Budget', 'Hiring', 'Operations'],
            participantVotes: [
                [1n, 10n, 1n],
                [10n, 1n, 10n],
                [5n, 5n, 5n],
            ],
        },
        expectedExcluded: [],
        expectedAcceptedCount: 3,
    },
    {
        name: 'verifies an X25519 ceremony with mixed edge scores',
        scenario: {
            participantCount: 5,
            optionList: ['Alpha', 'Beta', 'Gamma'],
            participantVotes: [
                [1n, 10n, 3n],
                [10n, 1n, 8n],
                [2n, 9n, 4n],
                [9n, 2n, 7n],
                [5n, 5n, 6n],
            ],
            transportSuite: 'X25519' as const,
        },
        expectedExcluded: [],
        expectedAcceptedCount: 5,
    },
] as const;

describe('public voting flow', () => {
    let fullFixture: Awaited<ReturnType<typeof runVotingFlowScenario>>;
    let partialFixture: Awaited<ReturnType<typeof runVotingFlowScenario>>;

    beforeAll(async () => {
        [fullFixture, partialFixture] = await Promise.all([
            runVotingFlowScenario({
                participantCount: 5,
                optionList: ['One', 'Two', 'Three'],
                participantVotes: [
                    [1n, 2n, 3n],
                    [4n, 5n, 6n],
                    [7n, 8n, 9n],
                    [10n, 1n, 2n],
                    [3n, 4n, 5n],
                ],
            }),
            runVotingFlowScenario({
                participantCount: 5,
                optionList: ['One', 'Two', 'Three'],
                participantVotes: [
                    [1n, 2n, 3n],
                    [4n, 5n, 6n],
                    [7n, 8n, 9n],
                    [10n, 1n, 2n],
                    [3n, 4n, 5n],
                ],
                votingParticipantIndices: [1, 2, 3, 4],
                closeParticipantIndices: [1, 2, 3, 4],
            }),
        ]);
    }, fixtureTimeoutMs);

    it.concurrent.each(positiveScenarios)(
        '$name',
        async (entry) => {
            const result = await runVotingFlowScenario(entry.scenario);

            expect(result.threshold).toBe(
                majorityThreshold(entry.scenario.participantCount),
            );
            expect(result.verified.dkg.participantCount).toBe(
                entry.scenario.participantCount,
            );
            expect(result.verified.dkg.threshold).toBe(result.threshold);
            expect(result.verified.countedParticipantIndices).toEqual(
                result.countedParticipantIndices,
            );
            expect(result.verified.excludedParticipantIndices).toEqual(
                entry.expectedExcluded,
            );
            expect(
                result.verified.perOptionAcceptedCounts.map(
                    (option) => option.acceptedCount,
                ),
            ).toEqual(
                Array.from(
                    { length: result.manifest.optionList.length },
                    () => entry.expectedAcceptedCount,
                ),
            );
            expect(
                result.verified.perOptionTallies.map((option) => option.tally),
            ).toEqual(result.expectedTallies);
            expect(
                result.verified.boardAudit.ballotClose.acceptedPayloads,
            ).toHaveLength(1);
        },
        fixtureTimeoutMs,
    );

    it('rejects vote rows with too few option scores before the full flow completes', async () => {
        await expect(
            runVotingFlowScenario({
                participantCount: 3,
                optionList: ['Alpha', 'Beta', 'Gamma'],
                participantVotes: [
                    [1n, 2n, 3n],
                    [4n, 5n],
                    [6n, 7n, 8n],
                ],
            }),
        ).rejects.toThrow(
            'Participant 2 vote row must include exactly 3 option scores',
        );
    });

    it('rejects vote rows outside the shipped 1..10 score domain', async () => {
        await expect(
            runVotingFlowScenario({
                participantCount: 3,
                optionList: ['Alpha', 'Beta'],
                participantVotes: [
                    [0n, 2n],
                    [4n, 5n],
                    [6n, 7n],
                ],
            }),
        ).rejects.toThrow();
        await expect(
            runVotingFlowScenario({
                participantCount: 3,
                optionList: ['Alpha', 'Beta'],
                participantVotes: [
                    [1n, 2n],
                    [4n, 11n],
                    [6n, 7n],
                ],
            }),
        ).rejects.toThrow();
    });

    it('rejects manifest option metadata that no longer belongs on the public manifest', () => {
        expect(() =>
            createElectionManifest({
                rosterHash: 'roster-hash',
                optionList: ['Alpha', 'Beta'],
                participantCount: 3,
            } as unknown as Parameters<typeof createElectionManifest>[0]),
        ).toThrow(
            'Legacy manifest field "participantCount" is not supported on the Ristretto beta line',
        );
    });

    it('rejects ballot close payloads signed by a non-organizer', async () => {
        const forgedBallotClosePayload = await signProtocolPayload(
            fullFixture.participants[1].auth.privateKey,
            {
                sessionId: fullFixture.sessionId,
                manifestHash: fullFixture.manifestHash,
                phase: 6,
                participantIndex: fullFixture.participants[1].index,
                messageType: 'ballot-close',
                includedParticipantIndices:
                    fullFixture.countedParticipantIndices,
            },
        );

        await expect(
            verifyElectionCeremonyDetailed({
                manifest: fullFixture.manifest,
                sessionId: fullFixture.sessionId,
                dkgTranscript: fullFixture.dkgTranscript,
                ballotPayloads: fullFixture.ballotPayloads,
                ballotClosePayload: forgedBallotClosePayload,
                decryptionSharePayloads: fullFixture.decryptionSharePayloads,
                tallyPublications: fullFixture.tallyPublications,
            }),
        ).rejects.toThrow('Ballot close must be signed by organizer 1');
    });

    it('rejects ballot close payloads with duplicate or unsorted participant indices', async () => {
        const duplicateBallotClosePayload = await signProtocolPayload(
            fullFixture.participants[0].auth.privateKey,
            {
                sessionId: fullFixture.sessionId,
                manifestHash: fullFixture.manifestHash,
                phase: 6,
                participantIndex: fullFixture.participants[0].index,
                messageType: 'ballot-close',
                includedParticipantIndices: [1, 2, 2, 3],
            },
        );
        const unsortedBallotClosePayload = await signProtocolPayload(
            fullFixture.participants[0].auth.privateKey,
            {
                sessionId: fullFixture.sessionId,
                manifestHash: fullFixture.manifestHash,
                phase: 6,
                participantIndex: fullFixture.participants[0].index,
                messageType: 'ballot-close',
                includedParticipantIndices: [1, 3, 2, 4, 5],
            },
        );

        await expect(
            verifyElectionCeremonyDetailed({
                manifest: fullFixture.manifest,
                sessionId: fullFixture.sessionId,
                dkgTranscript: fullFixture.dkgTranscript,
                ballotPayloads: fullFixture.ballotPayloads,
                ballotClosePayload: duplicateBallotClosePayload,
                decryptionSharePayloads: fullFixture.decryptionSharePayloads,
                tallyPublications: fullFixture.tallyPublications,
            }),
        ).rejects.toThrow('Ballot close participant indices must be unique');
        await expect(
            verifyElectionCeremonyDetailed({
                manifest: fullFixture.manifest,
                sessionId: fullFixture.sessionId,
                dkgTranscript: fullFixture.dkgTranscript,
                ballotPayloads: fullFixture.ballotPayloads,
                ballotClosePayload: unsortedBallotClosePayload,
                decryptionSharePayloads: fullFixture.decryptionSharePayloads,
                tallyPublications: fullFixture.tallyPublications,
            }),
        ).rejects.toThrow(
            'Ballot close participant indices must be strictly increasing',
        );
    });

    it('rejects ballot close payloads that include fewer than the derived threshold participants', async () => {
        const belowThresholdBallotClosePayload = await signProtocolPayload(
            fullFixture.participants[0].auth.privateKey,
            {
                sessionId: fullFixture.sessionId,
                manifestHash: fullFixture.manifestHash,
                phase: 6,
                participantIndex: fullFixture.participants[0].index,
                messageType: 'ballot-close',
                includedParticipantIndices: [1, 2],
            },
        );

        await expect(
            verifyElectionCeremonyDetailed({
                manifest: fullFixture.manifest,
                sessionId: fullFixture.sessionId,
                dkgTranscript: fullFixture.dkgTranscript,
                ballotPayloads: fullFixture.ballotPayloads,
                ballotClosePayload: belowThresholdBallotClosePayload,
                decryptionSharePayloads: fullFixture.decryptionSharePayloads,
                tallyPublications: fullFixture.tallyPublications,
            }),
        ).rejects.toThrow('Ballot close must include at least 3 participants');
    });

    it('rejects ballot close payloads that include a participant without a complete ballot', async () => {
        const incompleteBallotClosePayload = await signProtocolPayload(
            partialFixture.participants[0].auth.privateKey,
            {
                sessionId: partialFixture.sessionId,
                manifestHash: partialFixture.manifestHash,
                phase: 6,
                participantIndex: partialFixture.participants[0].index,
                messageType: 'ballot-close',
                includedParticipantIndices: [1, 2, 3, 5],
            },
        );

        await expect(
            verifyElectionCeremonyDetailed({
                manifest: partialFixture.manifest,
                sessionId: partialFixture.sessionId,
                dkgTranscript: partialFixture.dkgTranscript,
                ballotPayloads: partialFixture.ballotPayloads,
                ballotClosePayload: incompleteBallotClosePayload,
                decryptionSharePayloads: partialFixture.decryptionSharePayloads,
                tallyPublications: partialFixture.tallyPublications,
            }),
        ).rejects.toThrow(
            'Ballot close requires a complete ballot from participant 5',
        );
    });

    it('rejects decryption shares tied to a different counted ballot transcript', async () => {
        const forgedDecryptionSharePayload = await createDecryptionSharePayload(
            fullFixture.participants[0].auth.privateKey,
            {
                ...fullFixture.decryptionSharePayloads[0].payload,
                transcriptHash: 'aa'.repeat(32),
            },
        );

        await expect(
            verifyElectionCeremonyDetailed({
                manifest: fullFixture.manifest,
                sessionId: fullFixture.sessionId,
                dkgTranscript: fullFixture.dkgTranscript,
                ballotPayloads: fullFixture.ballotPayloads,
                ballotClosePayload: fullFixture.ballotClosePayload,
                decryptionSharePayloads: [
                    forgedDecryptionSharePayload,
                    ...fullFixture.decryptionSharePayloads.slice(1),
                ],
                tallyPublications: fullFixture.tallyPublications,
            }),
        ).rejects.toThrow(
            'Decryption share transcript hash mismatch for participant 1 and option 1',
        );
    });

    it('rejects tally publications that do not match the recomputed close-selected tally', async () => {
        const forgedTallyPublication = await createTallyPublicationPayload(
            fullFixture.participants[0].auth.privateKey,
            {
                ...fullFixture.tallyPublications[0].payload,
                tally: fullFixture.expectedTallies[0] + 1n,
            },
        );

        await expect(
            verifyElectionCeremonyDetailed({
                manifest: fullFixture.manifest,
                sessionId: fullFixture.sessionId,
                dkgTranscript: fullFixture.dkgTranscript,
                ballotPayloads: fullFixture.ballotPayloads,
                ballotClosePayload: fullFixture.ballotClosePayload,
                decryptionSharePayloads: fullFixture.decryptionSharePayloads,
                tallyPublications: [
                    forgedTallyPublication,
                    ...fullFixture.tallyPublications.slice(1),
                ],
            }),
        ).rejects.toThrow(
            'Tally publication does not match the recomputed tally for option 1',
        );
    });
});
