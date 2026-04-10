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
    type ComplaintResolutionPayload,
    hashProtocolTranscript,
    type KeyDerivationConfirmation,
    type ProtocolPayload,
    type SignedPayload,
} from '#protocol';
import { generateTransportKeyPair, signPayloadBytes } from '#transport';
import { exportTransportPrivateKey } from '#transport-advanced';
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
    let completedWithoutConfirmations: CompletedVotingFlowResult;
    let withDealerFaultComplaint: CompletedVotingFlowResult;
    let withResolvedComplaint: CompletedVotingFlowResult;
    let withResolvedComplaintAndConfirmations: CompletedVotingFlowResult;
    beforeAll(async () => {
        const completedResult = await runVotingFlowScenario({
            participantCount: 3,
            votes: [1n, 2n, 3n],
            includeKeyDerivationConfirmations: true,
        });
        const completedWithoutConfirmationsResult = await runVotingFlowScenario(
            {
                participantCount: 3,
                votes: [1n, 2n, 3n],
            },
        );
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
        const resolvedComplaintWithConfirmationsResult =
            await runVotingFlowScenario({
                participantCount: 3,
                votes: [1n, 2n, 3n],
                includeKeyDerivationConfirmations: true,
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
        completedWithoutConfirmations = expectCompleted(
            completedWithoutConfirmationsResult,
            'Expected the no-confirmation fixture scenario to finish',
        );
        withDealerFaultComplaint = expectCompleted(
            dealerFaultComplaintResult,
            'Expected the dealer-fault complaint fixture scenario to finish',
        );
        withResolvedComplaint = expectCompleted(
            resolvedComplaintResult,
            'Expected the resolved complaint fixture scenario to finish',
        );
        withResolvedComplaintAndConfirmations = expectCompleted(
            resolvedComplaintWithConfirmationsResult,
            'Expected the resolved complaint fixture scenario with confirmations to finish',
        );
    }, 180000);
    it('verifies completed transcripts and derives the same ceremony material', async () => {
        const verified = await verifyDKGTranscript({
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
    it('accepts checkpointed transcripts without key-derivation confirmations', async () => {
        const verified = await verifyDKGTranscript({
            transcript: completedWithoutConfirmations.dkgTranscript,
            manifest: completedWithoutConfirmations.manifest,
            sessionId: completedWithoutConfirmations.sessionId,
        });
        expect(verified.qual).toEqual(
            completedWithoutConfirmations.finalState.qual,
        );
        expect(verified.derivedPublicKey).toBe(
            completedWithoutConfirmations.jointPublicKey,
        );
    });
    it('treats unresolved complaints as dealer-fault outcomes and derives QUAL reductions', async () => {
        const verified = await verifyDKGTranscript({
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
            transcript: withResolvedComplaintAndConfirmations.dkgTranscript,
            manifest: withResolvedComplaintAndConfirmations.manifest,
            sessionId: withResolvedComplaintAndConfirmations.sessionId,
        });
        expect(verified.acceptedComplaints).toEqual([]);
        expect(verified.qual).toEqual([1, 2, 3]);
    });
    it('treats malformed or mismatched complaint resolutions as unresolved complaints instead of transcript-fatal errors', async () => {
        const resolutionFixture = withResolvedComplaintAndConfirmations;
        const resolutionIndex = resolutionFixture.dkgTranscript.findIndex(
            (entry) => entry.payload.messageType === 'complaint-resolution',
        );
        if (resolutionIndex < 0) {
            throw new Error(
                'Expected the resolved complaint fixture transcript',
            );
        }
        const originalResolution = resolutionFixture.dkgTranscript[
            resolutionIndex
        ] as SignedPayload<ComplaintResolutionPayload>;
        const wrongEphemeralKey = await generateTransportKeyPair({
            suite: 'P-256',
            extractable: true,
        });
        const wrongResolution = await resignPayload(resolutionFixture, {
            ...originalResolution.payload,
            revealedEphemeralPrivateKey: await exportTransportPrivateKey(
                wrongEphemeralKey.privateKey,
            ),
        } as ProtocolPayload);
        const malformedResolution = await resignPayload(resolutionFixture, {
            ...originalResolution.payload,
            revealedEphemeralPrivateKey: '00'.repeat(
                67,
            ) as typeof originalResolution.payload.revealedEphemeralPrivateKey,
        } as ProtocolPayload);
        for (const replacement of [wrongResolution, malformedResolution]) {
            const complaintAdjustedTranscript = resolutionFixture.dkgTranscript
                .map((entry, index) =>
                    index === resolutionIndex ? replacement : entry,
                )
                .filter(
                    (entry) =>
                        entry.payload.messageType !== 'phase-checkpoint' &&
                        !(
                            entry.payload.messageType ===
                                'key-derivation-confirmation' &&
                            entry.payload.participantIndex === 1
                        ),
                );
            const updatedQualHash = await hashProtocolTranscript(
                complaintAdjustedTranscript
                    .filter(
                        (entry) =>
                            entry.payload.messageType !==
                            'key-derivation-confirmation',
                    )
                    .map((entry) => entry.payload),
                resolutionFixture.group.byteLength,
            );
            const updatedTranscript = await Promise.all(
                complaintAdjustedTranscript.map((entry) =>
                    entry.payload.messageType === 'key-derivation-confirmation'
                        ? resignPayload(resolutionFixture, {
                              ...entry.payload,
                              qualHash: updatedQualHash,
                              publicKey:
                                  withDealerFaultComplaint.jointPublicKey,
                          } as ProtocolPayload)
                        : Promise.resolve(entry),
                ),
            );
            const verified = await verifyDKGTranscript({
                transcript: updatedTranscript,
                manifest: resolutionFixture.manifest,
                sessionId: resolutionFixture.sessionId,
            });
            expect(verified.acceptedComplaints).toHaveLength(1);
            expect(verified.acceptedComplaints[0].dealerIndex).toBe(1);
            expect(verified.qual).toEqual([2, 3]);
        }
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
                transcript: missingEnvelope,
                manifest: completed.manifest,
                sessionId: completed.sessionId,
            }),
        ).rejects.toThrow(
            'Phase 1 checkpoint transcript hash does not match the signed transcript snapshot',
        );
        await expect(
            verifyDKGTranscript({
                transcript: missingFeldman,
                manifest: completed.manifest,
                sessionId: completed.sessionId,
            }),
        ).rejects.toThrow(
            'Phase 3 checkpoint transcript hash does not match the signed transcript snapshot',
        );
    });
    it('rejects self-targeted encrypted share payloads even when the payload count still matches', async () => {
        const selfTargetIndex = completed.dkgTranscript.findIndex(
            (entry) =>
                entry.payload.messageType === 'encrypted-dual-share' &&
                entry.payload.participantIndex === 1 &&
                entry.payload.recipientIndex === 2,
        );
        if (selfTargetIndex < 0) {
            throw new Error('Expected an encrypted share from dealer 1 to 2');
        }
        const selfTargetPayload = await resignPayload(completed, {
            ...completed.dkgTranscript[selfTargetIndex].payload,
            recipientIndex: 1,
            envelopeId: 'env-1-1',
        } as ProtocolPayload);
        await expect(
            verifyDKGTranscript({
                transcript: completed.dkgTranscript.map((entry, index) =>
                    index === selfTargetIndex ? selfTargetPayload : entry,
                ),
                manifest: completed.manifest,
                sessionId: completed.sessionId,
            }),
        ).rejects.toThrow(
            'Encrypted share payload for dealer 1 must target a different recipient',
        );
    });
    it('rejects wrong dealer-to-recipient coverage even when the encrypted share count still matches', async () => {
        const missingCoverageIndex = completed.dkgTranscript.findIndex(
            (entry) =>
                entry.payload.messageType === 'encrypted-dual-share' &&
                entry.payload.participantIndex === 1 &&
                entry.payload.recipientIndex === 2,
        );
        const duplicateCoveragePayload = completed.dkgTranscript.find(
            (entry) =>
                entry.payload.messageType === 'encrypted-dual-share' &&
                entry.payload.participantIndex === 1 &&
                entry.payload.recipientIndex === 3,
        );
        if (
            missingCoverageIndex < 0 ||
            duplicateCoveragePayload === undefined
        ) {
            throw new Error('Expected an encrypted share from dealer 1 to 2');
        }
        await expect(
            verifyDKGTranscript({
                transcript: completed.dkgTranscript.map((entry, index) =>
                    index === missingCoverageIndex
                        ? duplicateCoveragePayload
                        : entry,
                ),
                manifest: completed.manifest,
                sessionId: completed.sessionId,
            }),
        ).rejects.toThrow(
            'Phase 1 checkpoint transcript hash does not match the signed transcript snapshot',
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
                transcript: badSignatureTranscript,
                manifest: completed.manifest,
                sessionId: completed.sessionId,
            }),
        ).rejects.toThrow(
            'Payload signature failed verification for participant 1 (manifest-publication)',
        );
        await expect(
            verifyDKGTranscript({
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
                transcript: forgedTranscript,
                manifest: withResolvedComplaint.manifest,
                sessionId: withResolvedComplaint.sessionId,
            }),
        ).rejects.toThrow(
            'Complaint references an unknown envelope unknown-envelope',
        );
        await expect(
            verifyDKGTranscript({
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
