import { beforeAll, describe, expect, it } from 'vitest';

import {
    runVotingFlowScenario,
    type CompletedVotingFlowResult,
    type VotingFlowResult,
} from '../integration/voting-flow-harness.js';

import {
    canonicalUnsignedPayloadBytes,
    verifyPublishedVotingResult,
    type ProtocolPayload,
    type SignedPayload,
} from '#protocol';
import { signPayloadBytes } from '#transport';

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
    }, 90_000);

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
});
