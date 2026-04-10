import type { EnvelopeArtifact, ParticipantRuntime } from './types.js';

import {
    canonicalUnsignedPayloadBytes,
    hashProtocolPhaseSnapshot,
    hashRosterEntries,
    type ComplaintResolutionPayload,
    type ElectionManifest,
    type ManifestPublicationPayload,
    type PhaseCheckpointPayload,
    type ProtocolPayload,
    type SignedPayload,
} from '#protocol';
import { decodePedersenShareEnvelope } from '#src/dkg/pedersen-share-codec';
import { signPayloadBytes, verifyPayloadSignature } from '#transport';
import type { PedersenShare } from '#vss';

export const invariant: (
    condition: boolean,
    message: string,
) => asserts condition = (condition, message) => {
    if (!condition) {
        throw new Error(message);
    }
};

export const signPayload = async <TPayload extends ProtocolPayload>(
    privateKey: CryptoKey,
    payload: TPayload,
): Promise<SignedPayload<TPayload>> => ({
    payload,
    signature: await signPayloadBytes(
        privateKey,
        canonicalUnsignedPayloadBytes(payload),
    ),
});

export const createManifestPublicationPayload = async (
    publisher: ParticipantRuntime,
    sessionId: string,
    manifestHash: string,
    manifest: ElectionManifest,
): Promise<SignedPayload<ManifestPublicationPayload>> =>
    signPayload(publisher.auth.privateKey, {
        sessionId,
        manifestHash,
        phase: 0,
        participantIndex: publisher.index,
        messageType: 'manifest-publication',
        manifest,
    });

export const verifySignedTranscript = async (
    participants: readonly ParticipantRuntime[],
    signedPayloads: readonly SignedPayload[],
): Promise<void> => {
    const participantMap = new Map(
        participants.map((participant) => [participant.index, participant]),
    );

    const verifications = await Promise.all(
        signedPayloads.map(async (signedPayload) => {
            const participant = participantMap.get(
                signedPayload.payload.participantIndex,
            );
            invariant(
                participant !== undefined,
                `Missing participant ${signedPayload.payload.participantIndex} for signature verification`,
            );

            return verifyPayloadSignature(
                participant.auth.publicKey,
                canonicalUnsignedPayloadBytes(signedPayload.payload),
                signedPayload.signature,
            );
        }),
    );

    invariant(
        verifications.every(Boolean),
        'One or more signed protocol payloads failed verification',
    );
};

export const computeRosterHash = async (
    participants: readonly ParticipantRuntime[],
): Promise<string> =>
    hashRosterEntries(
        participants.map((participant) => ({
            participantIndex: participant.index,
            authPublicKey: participant.authPublicKeyHex,
            transportPublicKey: participant.transportPublicKeyHex,
        })),
    );

export const parseShareEnvelope = (
    plaintext: Uint8Array,
    expectedIndex: number,
): PedersenShare =>
    decodePedersenShareEnvelope(
        plaintext,
        expectedIndex,
        'Expected share envelope',
    );

export const createComplaintResolutionPayload = async (
    dealer: ParticipantRuntime,
    sessionId: string,
    manifestHash: string,
    complainantIndex: number,
    envelopeArtifact: EnvelopeArtifact,
): Promise<SignedPayload<ComplaintResolutionPayload>> =>
    signPayload(dealer.auth.privateKey, {
        sessionId,
        manifestHash,
        phase: 2,
        participantIndex: dealer.index,
        messageType: 'complaint-resolution',
        dealerIndex: dealer.index,
        complainantIndex,
        envelopeId: envelopeArtifact.envelope.envelopeId,
        suite: envelopeArtifact.envelope.suite,
        revealedEphemeralPrivateKey: envelopeArtifact.ephemeralPrivateKey,
    } satisfies ComplaintResolutionPayload);

export const createPhaseCheckpointPayload = async (
    signer: ParticipantRuntime,
    sessionId: string,
    manifestHash: string,
    transcript: readonly SignedPayload[],
    checkpointPhase: 0 | 1 | 2 | 3,
    qualParticipantIndices: readonly number[],
): Promise<SignedPayload<PhaseCheckpointPayload>> =>
    signPayload(signer.auth.privateKey, {
        sessionId,
        manifestHash,
        phase: checkpointPhase,
        participantIndex: signer.index,
        messageType: 'phase-checkpoint',
        checkpointPhase,
        checkpointTranscriptHash: await hashProtocolPhaseSnapshot(
            transcript.map((entry) => entry.payload),
            checkpointPhase,
        ),
        qualParticipantIndices,
    });
