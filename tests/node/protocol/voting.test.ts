import { beforeAll, describe, expect, it } from 'vitest';

import {
    runVotingFlowScenario,
    type CompletedVotingFlowResult,
    type VotingFlowResult,
} from '../integration/voting-flow-harness.js';

import {
    canonicalUnsignedPayloadBytes,
    verifyPublishedVotingResults,
    verifyPublishedVotingResult,
    type ProtocolPayload,
    type SignedPayload,
} from '#protocol';
import { signPayloadBytes } from '#transport';

const fixtureTimeoutMs = 180_000;

const expectCompleted = (
    result: VotingFlowResult,
    label: string,
): CompletedVotingFlowResult => {
    if (result.finalState.phase !== 'completed') {
        throw new Error(label);
    }

    return result as CompletedVotingFlowResult;
};

const resignPayload = async <TPayload extends ProtocolPayload>(
    result: CompletedVotingFlowResult,
    payload: TPayload,
): Promise<SignedPayload<TPayload>> => {
    const signer = result.participantAuthKeys.find(
        (candidate) => candidate.index === payload.participantIndex,
    );
    if (signer === undefined) {
        throw new Error(
            `Missing auth key for participant ${payload.participantIndex}`,
        );
    }

    return {
        payload,
        signature: await signPayloadBytes(
            signer.privateKey,
            canonicalUnsignedPayloadBytes(payload),
        ),
    };
};

describe('published voting verification', () => {
    let completed: CompletedVotingFlowResult;
    let multiOption: CompletedVotingFlowResult;
    let withDealerFaultComplaint: CompletedVotingFlowResult;

    beforeAll(async () => {
        completed = expectCompleted(
            await runVotingFlowScenario({
                participantCount: 3,
                scoreDomainMax: 3,
                votes: [3n, 2n, 1n],
                decryptionParticipantIndices: [1, 3],
            }),
            'Expected the baseline voting fixture to complete',
        );
        withDealerFaultComplaint = expectCompleted(
            await runVotingFlowScenario({
                participantCount: 3,
                scoreDomainMax: 3,
                votes: [3n, 1n, 2n],
                complaints: [
                    {
                        dealerIndex: 1,
                        recipientIndex: 2,
                        envelopeTamper: 'ciphertext',
                    },
                ],
                decryptionParticipantIndices: [2, 3],
            }),
            'Expected the dealer-fault voting fixture to complete',
        );
        multiOption = expectCompleted(
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
            'Expected the multi-option voting fixture to complete',
        );
    }, fixtureTimeoutMs);

    it(
        'verifies the typed ballot, decryption-share, and tally payloads end to end',
        {
            timeout: 20_000,
        },
        async () => {
            await expect(
                verifyPublishedVotingResult({
                    protocol: 'gjkr',
                    manifest: completed.manifest,
                    sessionId: completed.sessionId,
                    dkgTranscript: completed.dkgTranscript,
                    ballotPayloads: completed.ballotPayloads!,
                    decryptionSharePayloads: completed.decryptionSharePayloads!,
                    tallyPublication: completed.tallyPublication,
                }),
            ).resolves.toMatchObject({
                tally: 6n,
            });
        },
    );

    it(
        'verifies the same safe surface after a dealer-fault complaint reduces QUAL',
        {
            timeout: 20_000,
        },
        async () => {
            await expect(
                verifyPublishedVotingResult({
                    protocol: 'gjkr',
                    manifest: withDealerFaultComplaint.manifest,
                    sessionId: withDealerFaultComplaint.sessionId,
                    dkgTranscript: withDealerFaultComplaint.dkgTranscript,
                    ballotPayloads: withDealerFaultComplaint.ballotPayloads!,
                    decryptionSharePayloads:
                        withDealerFaultComplaint.decryptionSharePayloads!,
                    tallyPublication: withDealerFaultComplaint.tallyPublication,
                }),
            ).resolves.toMatchObject({
                tally: 6n,
            });
        },
    );

    it(
        'rejects duplicate ballot slots in the typed ballot transcript',
        {
            timeout: 20_000,
        },
        async () => {
            await expect(
                verifyPublishedVotingResult({
                    protocol: 'gjkr',
                    manifest: completed.manifest,
                    sessionId: completed.sessionId,
                    dkgTranscript: completed.dkgTranscript,
                    ballotPayloads: [
                        ...completed.ballotPayloads!,
                        completed.ballotPayloads![0],
                    ],
                    decryptionSharePayloads: completed.decryptionSharePayloads!,
                    tallyPublication: completed.tallyPublication,
                }),
            ).rejects.toThrow('Duplicate ballot slot 1:1 is not allowed');
        },
    );

    it(
        'rejects decryption shares tied to a different local aggregate transcript',
        {
            timeout: 20_000,
        },
        async () => {
            const wrongShare = await resignPayload(completed, {
                ...completed.decryptionSharePayloads![0].payload,
                transcriptHash: '00'.repeat(32),
            });

            await expect(
                verifyPublishedVotingResult({
                    protocol: 'gjkr',
                    manifest: completed.manifest,
                    sessionId: completed.sessionId,
                    dkgTranscript: completed.dkgTranscript,
                    ballotPayloads: completed.ballotPayloads!,
                    decryptionSharePayloads: [
                        wrongShare,
                        ...completed.decryptionSharePayloads!.slice(1),
                    ],
                    tallyPublication: completed.tallyPublication,
                }),
            ).rejects.toThrow(
                'Decryption share transcript hash mismatch for participant 1',
            );
        },
    );

    it(
        'rejects tally publications that do not match the recomputed tally',
        {
            timeout: 20_000,
        },
        async () => {
            const wrongPublication = await resignPayload(completed, {
                ...completed.tallyPublication!.payload,
                tally: '00'.repeat(
                    completed.tallyPublication!.payload.tally.length / 2,
                ),
            });

            await expect(
                verifyPublishedVotingResult({
                    protocol: 'gjkr',
                    manifest: completed.manifest,
                    sessionId: completed.sessionId,
                    dkgTranscript: completed.dkgTranscript,
                    ballotPayloads: completed.ballotPayloads!,
                    decryptionSharePayloads: completed.decryptionSharePayloads!,
                    tallyPublication: wrongPublication,
                }),
            ).rejects.toThrow(
                'Tally publication does not match the recomputed tally',
            );
        },
    );

    it(
        'verifies multi-option published tallies and supports arithmetic-mean derivation in the caller',
        {
            timeout: 30_000,
        },
        async () => {
            const verified = await verifyPublishedVotingResults({
                protocol: 'gjkr',
                manifest: multiOption.manifest,
                sessionId: multiOption.sessionId,
                dkgTranscript: multiOption.dkgTranscript,
                ballotPayloads: multiOption.ballotPayloads!,
                decryptionSharePayloads: multiOption.decryptionSharePayloads!,
                tallyPublications: multiOption.tallyPublications,
            });

            expect(verified.options.map((entry) => entry.optionIndex)).toEqual([
                1, 2, 3,
            ]);
            expect(verified.options.map((entry) => entry.tally)).toEqual([
                11n,
                9n,
                9n,
            ]);
            expect(
                verified.options.map(
                    (entry) =>
                        Number(entry.tally) /
                        entry.ballots.aggregate.ballotCount,
                ),
            ).toEqual([2.2, 1.8, 1.8]);
        },
    );

    it(
        'rejects the single-option wrapper when the manifest carries multiple options',
        {
            timeout: 20_000,
        },
        async () => {
            await expect(
                verifyPublishedVotingResult({
                    protocol: 'gjkr',
                    manifest: multiOption.manifest,
                    sessionId: multiOption.sessionId,
                    dkgTranscript: multiOption.dkgTranscript,
                    ballotPayloads: multiOption.ballotPayloads!,
                    decryptionSharePayloads:
                        multiOption.decryptionSharePayloads!,
                    tallyPublication: multiOption.tallyPublication,
                }),
            ).rejects.toThrow(
                'verifyPublishedVotingResult requires a single-option manifest',
            );
        },
    );

    it(
        'rejects wrong ballot option bindings and duplicate per-option ballot slots',
        {
            timeout: 30_000,
        },
        async () => {
            const wrongBinding = await resignPayload(multiOption, {
                ...multiOption.ballotPayloads![0].payload,
                optionIndex: 2,
            });

            await expect(
                verifyPublishedVotingResults({
                    protocol: 'gjkr',
                    manifest: multiOption.manifest,
                    sessionId: multiOption.sessionId,
                    dkgTranscript: multiOption.dkgTranscript,
                    ballotPayloads: [
                        wrongBinding,
                        ...multiOption.ballotPayloads!.slice(1),
                    ],
                    decryptionSharePayloads:
                        multiOption.decryptionSharePayloads!,
                    tallyPublications: multiOption.tallyPublications,
                }),
            ).rejects.toThrow(
                'Option 2 ballot verification failed: Ballot proof failed verification for voter 1 option 2',
            );

            await expect(
                verifyPublishedVotingResults({
                    protocol: 'gjkr',
                    manifest: multiOption.manifest,
                    sessionId: multiOption.sessionId,
                    dkgTranscript: multiOption.dkgTranscript,
                    ballotPayloads: [
                        ...multiOption.ballotPayloads!,
                        multiOption.ballotPayloads![0],
                    ],
                    decryptionSharePayloads:
                        multiOption.decryptionSharePayloads!,
                    tallyPublications: multiOption.tallyPublications,
                }),
            ).rejects.toThrow(
                'Option 1 ballot verification failed: Duplicate ballot slot 1:1 is not allowed',
            );
        },
    );

    it(
        'rejects invalid option indices with protocol payload errors',
        {
            timeout: 30_000,
        },
        async () => {
            const invalidOptionIndex = await resignPayload(multiOption, {
                ...multiOption.ballotPayloads![0].payload,
                optionIndex: 0,
            });

            await expect(
                verifyPublishedVotingResults({
                    protocol: 'gjkr',
                    manifest: multiOption.manifest,
                    sessionId: multiOption.sessionId,
                    dkgTranscript: multiOption.dkgTranscript,
                    ballotPayloads: [
                        invalidOptionIndex,
                        ...multiOption.ballotPayloads!.slice(1),
                    ],
                    decryptionSharePayloads:
                        multiOption.decryptionSharePayloads!,
                    tallyPublications: multiOption.tallyPublications,
                }),
            ).rejects.toThrow(
                'Ballot submission option index must be a positive integer',
            );
        },
    );

    it(
        'adds option context when a multi-option ballot set falls below the publication floor',
        {
            timeout: 30_000,
        },
        async () => {
            await expect(
                verifyPublishedVotingResults({
                    protocol: 'gjkr',
                    manifest: multiOption.manifest,
                    sessionId: multiOption.sessionId,
                    dkgTranscript: multiOption.dkgTranscript,
                    ballotPayloads: multiOption.ballotPayloads!.filter(
                        (entry) => entry.payload.optionIndex !== 3,
                    ),
                    decryptionSharePayloads:
                        multiOption.decryptionSharePayloads!,
                    tallyPublications: multiOption.tallyPublications,
                }),
            ).rejects.toThrow(
                'Option 3 ballot verification failed: Accepted ballot count 0 is below the minimum publication threshold 4',
            );
        },
    );

    it(
        'rejects per-option transcript mismatches and insufficient per-option decryption subsets',
        {
            timeout: 30_000,
        },
        async () => {
            const optionOne = multiOption.optionResults?.find(
                (entry) => entry.optionIndex === 1,
            );
            const optionTwoShare = multiOption.decryptionSharePayloads?.find(
                (entry) => entry.payload.optionIndex === 2,
            );
            const optionThreeShares =
                multiOption.decryptionSharePayloads?.filter(
                    (entry) => entry.payload.optionIndex === 3,
                ) ?? [];

            expect(optionOne).toBeDefined();
            expect(optionTwoShare).toBeDefined();
            expect(optionThreeShares).toHaveLength(3);

            const wrongShare = await resignPayload(multiOption, {
                ...optionTwoShare!.payload,
                transcriptHash: optionOne!.ballotLogHash,
            });

            await expect(
                verifyPublishedVotingResults({
                    protocol: 'gjkr',
                    manifest: multiOption.manifest,
                    sessionId: multiOption.sessionId,
                    dkgTranscript: multiOption.dkgTranscript,
                    ballotPayloads: multiOption.ballotPayloads!,
                    decryptionSharePayloads: [
                        ...multiOption.decryptionSharePayloads!.filter(
                            (entry) => entry !== optionTwoShare,
                        ),
                        wrongShare,
                    ],
                    tallyPublications: multiOption.tallyPublications,
                }),
            ).rejects.toThrow(
                'Decryption share transcript hash mismatch for participant 1 and option 2',
            );

            await expect(
                verifyPublishedVotingResults({
                    protocol: 'gjkr',
                    manifest: multiOption.manifest,
                    sessionId: multiOption.sessionId,
                    dkgTranscript: multiOption.dkgTranscript,
                    ballotPayloads: multiOption.ballotPayloads!,
                    decryptionSharePayloads:
                        multiOption.decryptionSharePayloads!.filter(
                            (entry) =>
                                entry.payload.optionIndex !== 3 ||
                                entry !== optionThreeShares[0],
                        ),
                    tallyPublications: multiOption.tallyPublications,
                }),
            ).rejects.toThrow(
                'At least 3 decryption shares are required for option 3',
            );
        },
    );
});
