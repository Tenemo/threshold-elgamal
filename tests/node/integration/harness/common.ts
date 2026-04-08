import type { EnvelopeArtifact, ParticipantRuntime } from './types.js';

import {
    canonicalUnsignedPayloadBytes,
    hashRosterEntries,
    type ComplaintResolutionPayload,
    type ElectionManifest,
    type ManifestPublicationPayload,
    type ProtocolPayload,
    type SignedPayload,
} from '#protocol';
import { fixedHexToBigint } from '#serialize';
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
): PedersenShare => {
    const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as {
        readonly blindingValue: string;
        readonly index: number;
        readonly secretValue: string;
    };

    invariant(
        parsed.index === expectedIndex,
        `Expected share envelope for participant ${expectedIndex}, received ${parsed.index}`,
    );

    return {
        index: parsed.index,
        secretValue: fixedHexToBigint(parsed.secretValue),
        blindingValue: fixedHexToBigint(parsed.blindingValue),
    };
};

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
    });
