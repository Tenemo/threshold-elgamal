import { beforeAll, describe, expect, it } from 'vitest';

import {
    runVotingFlowScenario,
    type CompletedVotingFlowResult,
    type VotingFlowResult,
} from '../integration/voting-flow-harness.js';

import {
    deriveQualifiedParticipantIndices,
    deriveTranscriptVerificationKey,
    verifyDKGTranscript,
} from '#dkg';
import {
    canonicalUnsignedPayloadBytes,
    type KeyDerivationConfirmation,
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

const resignPayload = async (
    result: CompletedVotingFlowResult,
    payload: ProtocolPayload,
): Promise<SignedPayload> => {
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

describe('DKG transcript verification', () => {
    let completed: CompletedVotingFlowResult;
    let withDealerFaultComplaint: CompletedVotingFlowResult;
    let withResolvedComplaint: CompletedVotingFlowResult;

    beforeAll(async () => {
        const completedResult = await runVotingFlowScenario({
            participantCount: 3,
            votes: [1n, 2n, 3n],
        });
        const dealerFaultComplaintResult = await runVotingFlowScenario({
            participantCount: 3,
            votes: [1n, 2n, 3n],
            complaints: [
                {
                    dealerIndex: 1,
                    recipientIndex: 2,
                    envelopeTamper: 'ciphertext',
                },
            ],
        });
        const resolvedComplaintResult = await runVotingFlowScenario({
            participantCount: 3,
            votes: [1n, 2n, 3n],
            complaints: [
                {
                    dealerIndex: 1,
                    recipientIndex: 2,
                    resolutionOutcome: 'complainant-fault',
                },
            ],
        });

        completed = expectCompleted(
            completedResult,
            'Expected the completed fixture scenario to finish',
        );
        withDealerFaultComplaint = expectCompleted(
            dealerFaultComplaintResult,
            'Expected the dealer-fault complaint fixture scenario to finish',
        );
        withResolvedComplaint = expectCompleted(
            resolvedComplaintResult,
            'Expected the resolved complaint fixture scenario to finish',
        );
    }, 30_000);

    it('verifies completed transcripts and derives the same ceremony material', async () => {
        const verified = await verifyDKGTranscript({
            protocol: 'gjkr',
            transcript: completed.dkgTranscript,
            manifest: completed.manifest,
            sessionId: completed.sessionId,
        });

        expect(verified.qual).toEqual(completed.finalState.qual);
        expect(verified.derivedPublicKey).toBe(completed.jointPublicKey);
        expect(
            deriveQualifiedParticipantIndices(
                completed.manifest.participantCount,
                verified.acceptedComplaints,
            ),
        ).toEqual(verified.qual);
        expect(
            deriveTranscriptVerificationKey(
                verified.feldmanCommitments,
                completed.finalShares![0].index,
                completed.group,
            ),
        ).toBe(completed.transcriptDerivedVerificationKeys![0].value);
    });

    it('treats unresolved complaints as dealer-fault outcomes and derives QUAL reductions', async () => {
        const verified = await verifyDKGTranscript({
            protocol: 'gjkr',
            transcript: withDealerFaultComplaint.dkgTranscript,
            manifest: withDealerFaultComplaint.manifest,
            sessionId: withDealerFaultComplaint.sessionId,
        });

        expect(verified.acceptedComplaints).toHaveLength(1);
        expect(verified.acceptedComplaints[0].dealerIndex).toBe(1);
        expect(verified.qual).toEqual([2, 3]);
    });

    it('accepts valid complaint resolutions and keeps the dealer in QUAL', async () => {
        const verified = await verifyDKGTranscript({
            protocol: 'gjkr',
            transcript: withResolvedComplaint.dkgTranscript,
            manifest: withResolvedComplaint.manifest,
            sessionId: withResolvedComplaint.sessionId,
        });

        expect(verified.acceptedComplaints).toEqual([]);
        expect(verified.qual).toEqual([1, 2, 3]);
    });

    it('rejects missing encrypted shares and missing Feldman commitments', async () => {
        const missingEnvelope = completed.dkgTranscript.filter(
            (entry, index) =>
                !(
                    entry.payload.messageType === 'encrypted-dual-share' &&
                    index ===
                        completed.dkgTranscript.findIndex(
                            (candidate) =>
                                candidate.payload.messageType ===
                                'encrypted-dual-share',
                        )
                ),
        );
        const missingFeldman = completed.dkgTranscript.filter(
            (entry) =>
                !(
                    entry.payload.messageType === 'feldman-commitment' &&
                    entry.payload.participantIndex === 1
                ),
        );

        await expect(
            verifyDKGTranscript({
                protocol: 'gjkr',
                transcript: missingEnvelope,
                manifest: completed.manifest,
                sessionId: completed.sessionId,
            }),
        ).rejects.toThrow('Expected 6 encrypted share payloads, received 5');

        await expect(
            verifyDKGTranscript({
                protocol: 'gjkr',
                transcript: missingFeldman,
                manifest: completed.manifest,
                sessionId: completed.sessionId,
            }),
        ).rejects.toThrow(
            'Missing Feldman commitment payload for qualified dealer 1',
        );
    });

    it('rejects bad signatures and mismatched session identifiers', async () => {
        const badSignatureTranscript = completed.dkgTranscript.map(
            (entry, index) =>
                index === 0
                    ? {
                          ...entry,
                          signature: '00'.repeat(entry.signature.length / 2),
                      }
                    : entry,
        );

        await expect(
            verifyDKGTranscript({
                protocol: 'gjkr',
                transcript: badSignatureTranscript,
                manifest: completed.manifest,
                sessionId: completed.sessionId,
            }),
        ).rejects.toThrow(
            'Payload signature failed verification for participant 1 (manifest-publication)',
        );

        await expect(
            verifyDKGTranscript({
                protocol: 'gjkr',
                transcript: completed.dkgTranscript,
                manifest: completed.manifest,
                sessionId: `${completed.sessionId}-other`,
            }),
        ).rejects.toThrow(
            'Payload session does not match the verification input',
        );
    });

    it('rejects forged complaint evidence and unmatched complaint resolutions', async () => {
        const complaintIndex = withResolvedComplaint.dkgTranscript.findIndex(
            (entry) => entry.payload.messageType === 'complaint',
        );
        if (complaintIndex < 0) {
            throw new Error('Expected the complaint fixture transcript');
        }

        const originalComplaint =
            withResolvedComplaint.dkgTranscript[complaintIndex];
        const forgedComplaintPayload = {
            ...originalComplaint.payload,
            envelopeId: 'unknown-envelope',
        } as ProtocolPayload;
        const forgedComplaint = await resignPayload(
            withResolvedComplaint,
            forgedComplaintPayload,
        );
        const forgedTranscript = withResolvedComplaint.dkgTranscript.map(
            (entry, index) =>
                index === complaintIndex ? forgedComplaint : entry,
        );
        const unmatchedResolutionTranscript =
            withResolvedComplaint.dkgTranscript.filter(
                (entry) => entry.payload.messageType !== 'complaint',
            );

        await expect(
            verifyDKGTranscript({
                protocol: 'gjkr',
                transcript: forgedTranscript,
                manifest: withResolvedComplaint.manifest,
                sessionId: withResolvedComplaint.sessionId,
            }),
        ).rejects.toThrow(
            'Complaint references an unknown envelope unknown-envelope',
        );

        await expect(
            verifyDKGTranscript({
                protocol: 'gjkr',
                transcript: unmatchedResolutionTranscript,
                manifest: withResolvedComplaint.manifest,
                sessionId: withResolvedComplaint.sessionId,
            }),
        ).rejects.toThrow(
            'Complaint resolution for envelope env-1-2 does not match any complaint',
        );
    });

    it('rejects mismatched qual hashes and final public keys after signature verification', async () => {
        const confirmationIndex = completed.dkgTranscript.findIndex(
            (entry) =>
                entry.payload.messageType === 'key-derivation-confirmation',
        );
        if (confirmationIndex < 0) {
            throw new Error(
                'Expected a confirmation payload in the transcript',
            );
        }

        const originalConfirmation = completed.dkgTranscript[
            confirmationIndex
        ] as SignedPayload<KeyDerivationConfirmation>;
        const wrongQualHash = await resignPayload(completed, {
            ...originalConfirmation.payload,
            qualHash: '00'.repeat(32),
        } as ProtocolPayload);
        const wrongPublicKey = await resignPayload(completed, {
            ...originalConfirmation.payload,
            publicKey: 'f'.repeat(
                originalConfirmation.payload.publicKey.length,
            ),
        } as ProtocolPayload);

        await expect(
            verifyDKGTranscript({
                protocol: 'gjkr',
                transcript: completed.dkgTranscript.map((entry, index) =>
                    index === confirmationIndex ? wrongQualHash : entry,
                ),
                manifest: completed.manifest,
                sessionId: completed.sessionId,
            }),
        ).rejects.toThrow(
            `qualHash mismatch in confirmation from participant ${originalConfirmation.payload.participantIndex}`,
        );

        await expect(
            verifyDKGTranscript({
                protocol: 'gjkr',
                transcript: completed.dkgTranscript.map((entry, index) =>
                    index === confirmationIndex ? wrongPublicKey : entry,
                ),
                manifest: completed.manifest,
                sessionId: completed.sessionId,
            }),
        ).rejects.toThrow(
            `Joint public key mismatch in confirmation from participant ${originalConfirmation.payload.participantIndex}`,
        );
    });
});
