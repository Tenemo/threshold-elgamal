import { InvalidPayloadError, type CryptoGroup } from '../core/index.js';
import type { EncodedPoint } from '../core/types.js';
import type {
    ComplaintPayload,
    ComplaintResolutionPayload,
    EncryptedDualSharePayload,
    PedersenCommitmentPayload,
    SignedPayload,
} from '../protocol/types.js';
import type { VerifiedProtocolSignatures } from '../protocol/verification.js';
import { resolveDealerChallengeFromPublicKey } from '../transport/complaints.js';
import { verifyPedersenShare } from '../vss/pedersen.js';

import { decodePedersenShareEnvelope } from './pedersen-share-codec.js';
import type { DKGProtocol } from './types.js';
import {
    complaintResolutionKey,
    encryptedShareSlotKey,
    parseCommitmentVector,
    validateParticipantIndex,
} from './verification-shared.js';
import type {
    EncryptedShareMatrix,
    VerifyDKGTranscriptInput,
} from './verification-types.js';

export const buildEncryptedShareMatrix = (
    transcript: readonly SignedPayload[],
    participantCount: number,
): EncryptedShareMatrix => {
    const encryptedShares = transcript.filter(
        (payload): payload is SignedPayload<EncryptedDualSharePayload> =>
            payload.payload.messageType === 'encrypted-dual-share',
    );

    const bySlot = new Map<string, SignedPayload<EncryptedDualSharePayload>>();
    const byComplaintKey = new Map<
        string,
        SignedPayload<EncryptedDualSharePayload>
    >();

    for (const payload of encryptedShares) {
        const dealerIndex = payload.payload.participantIndex;
        const recipientIndex = payload.payload.recipientIndex;

        validateParticipantIndex(
            dealerIndex,
            participantCount,
            'Encrypted share dealer index',
        );
        validateParticipantIndex(
            recipientIndex,
            participantCount,
            'Encrypted share recipient index',
        );

        if (dealerIndex === recipientIndex) {
            throw new InvalidPayloadError(
                `Encrypted share payload for dealer ${dealerIndex} must target a different recipient`,
            );
        }

        const slotKey = encryptedShareSlotKey(dealerIndex, recipientIndex);
        if (bySlot.has(slotKey)) {
            throw new InvalidPayloadError(
                `Duplicate encrypted share payload for dealer ${dealerIndex} and recipient ${recipientIndex}`,
            );
        }
        bySlot.set(slotKey, payload);

        const complaintKey = complaintResolutionKey(
            recipientIndex,
            dealerIndex,
            payload.payload.envelopeId,
        );
        if (byComplaintKey.has(complaintKey)) {
            throw new InvalidPayloadError(
                `Duplicate encrypted share envelope ${payload.payload.envelopeId} for dealer ${dealerIndex} and recipient ${recipientIndex}`,
            );
        }
        byComplaintKey.set(complaintKey, payload);
    }

    return {
        encryptedShares,
        bySlot,
        byComplaintKey,
    };
};

export const assertEncryptedShareCoverage = (
    encryptedShareMatrix: EncryptedShareMatrix,
    participantIndices: readonly number[],
): void => {
    for (const dealerIndex of participantIndices) {
        for (const recipientIndex of participantIndices) {
            if (dealerIndex === recipientIndex) {
                continue;
            }

            if (
                !encryptedShareMatrix.bySlot.has(
                    encryptedShareSlotKey(dealerIndex, recipientIndex),
                )
            ) {
                throw new InvalidPayloadError(
                    `Missing encrypted share payload for dealer ${dealerIndex} and recipient ${recipientIndex}`,
                );
            }
        }
    }
};

export const parsePedersenCommitmentMap = (
    transcript: readonly SignedPayload[],
    protocol: DKGProtocol,
    threshold: number,
    group: CryptoGroup,
): ReadonlyMap<number, readonly EncodedPoint[]> => {
    const pedersenCommitments = transcript.filter(
        (payload): payload is SignedPayload<PedersenCommitmentPayload> =>
            payload.payload.messageType === 'pedersen-commitment',
    );
    if (protocol !== 'gjkr' && pedersenCommitments.length > 0) {
        throw new InvalidPayloadError(
            'Joint-Feldman transcripts must not include Pedersen commitments',
        );
    }

    const pedersenCommitmentMap = new Map<number, readonly EncodedPoint[]>();
    for (const payload of pedersenCommitments) {
        if (pedersenCommitmentMap.has(payload.payload.participantIndex)) {
            throw new InvalidPayloadError(
                `Pedersen commitment requires exactly one payload for participant ${payload.payload.participantIndex}`,
            );
        }
        pedersenCommitmentMap.set(
            payload.payload.participantIndex,
            parseCommitmentVector(
                payload.payload.commitments,
                threshold,
                group,
                'Pedersen commitment payload',
            ),
        );
    }

    return pedersenCommitmentMap;
};

export const assertPedersenCommitmentCoverage = (
    pedersenCommitmentMap: ReadonlyMap<number, readonly EncodedPoint[]>,
    dealerIndices: readonly number[],
): void => {
    for (const dealerIndex of dealerIndices) {
        if (!pedersenCommitmentMap.has(dealerIndex)) {
            throw new InvalidPayloadError(
                `Missing Pedersen commitment payload for dealer ${dealerIndex}`,
            );
        }
    }
};

const buildComplaintResolutionPayloadMap = (
    transcript: readonly SignedPayload[],
): {
    readonly complaintResolutionPayloads: readonly ComplaintResolutionPayload[];
    readonly resolutionPayloadMap: ReadonlyMap<
        string,
        ComplaintResolutionPayload
    >;
} => {
    const complaintResolutionPayloads = transcript
        .filter(
            (payload): payload is SignedPayload<ComplaintResolutionPayload> =>
                payload.payload.messageType === 'complaint-resolution',
        )
        .map((payload) => payload.payload);
    const resolutionPayloadMap = new Map<string, ComplaintResolutionPayload>();

    for (const resolutionPayload of complaintResolutionPayloads) {
        if (
            resolutionPayload.participantIndex !== resolutionPayload.dealerIndex
        ) {
            throw new InvalidPayloadError(
                `Complaint resolution for envelope ${resolutionPayload.envelopeId} must be authored by dealer ${resolutionPayload.dealerIndex}`,
            );
        }

        const key = complaintResolutionKey(
            resolutionPayload.complainantIndex,
            resolutionPayload.dealerIndex,
            resolutionPayload.envelopeId,
        );
        if (resolutionPayloadMap.has(key)) {
            throw new InvalidPayloadError(
                `Duplicate complaint resolution for envelope ${resolutionPayload.envelopeId}`,
            );
        }
        resolutionPayloadMap.set(key, resolutionPayload);
    }

    return {
        complaintResolutionPayloads,
        resolutionPayloadMap,
    };
};

export const verifyComplaintOutcomes = async (
    input: VerifyDKGTranscriptInput,
    verifiedSignatures: VerifiedProtocolSignatures,
    encryptedShareMatrix: EncryptedShareMatrix,
    pedersenCommitmentMap: ReadonlyMap<number, readonly EncodedPoint[]>,
    group: CryptoGroup,
    allowedParticipants: ReadonlySet<number>,
): Promise<readonly ComplaintPayload[]> => {
    const complaints = input.transcript
        .filter(
            (payload): payload is SignedPayload<ComplaintPayload> =>
                payload.payload.messageType === 'complaint',
        )
        .map((payload) => payload.payload);
    const { complaintResolutionPayloads, resolutionPayloadMap } =
        buildComplaintResolutionPayloadMap(input.transcript);
    const rosterEntryMap = new Map(
        verifiedSignatures.rosterEntries.map((entry) => [
            entry.participantIndex,
            entry,
        ]),
    );
    const acceptedComplaints: ComplaintPayload[] = [];
    const usedResolutionKeys = new Set<string>();

    for (const complaint of complaints) {
        if (
            !allowedParticipants.has(complaint.participantIndex) ||
            !allowedParticipants.has(complaint.dealerIndex)
        ) {
            throw new InvalidPayloadError(
                `Complaint participants must belong to the active DKG set for phase ${complaint.phase}`,
            );
        }

        const resolutionKey = complaintResolutionKey(
            complaint.participantIndex,
            complaint.dealerIndex,
            complaint.envelopeId,
        );
        const matchingEnvelope =
            encryptedShareMatrix.byComplaintKey.get(resolutionKey);
        if (matchingEnvelope === undefined) {
            throw new InvalidPayloadError(
                `Complaint references an unknown envelope ${complaint.envelopeId} for dealer ${complaint.dealerIndex} and complainant ${complaint.participantIndex}`,
            );
        }

        const resolutionPayload = resolutionPayloadMap.get(resolutionKey);
        if (resolutionPayload === undefined) {
            acceptedComplaints.push(complaint);
            continue;
        }

        usedResolutionKeys.add(resolutionKey);

        if (resolutionPayload.suite !== matchingEnvelope.payload.suite) {
            throw new InvalidPayloadError(
                `Complaint resolution suite mismatch for envelope ${complaint.envelopeId}`,
            );
        }

        const complainantRosterEntry = rosterEntryMap.get(
            complaint.participantIndex,
        );
        if (complainantRosterEntry === undefined) {
            throw new InvalidPayloadError(
                `Missing roster entry for complainant ${complaint.participantIndex}`,
            );
        }

        const resolution = await resolveDealerChallengeFromPublicKey(
            {
                ...matchingEnvelope.payload,
                dealerIndex: matchingEnvelope.payload.participantIndex,
                rosterHash: input.manifest.rosterHash,
                payloadType: 'encrypted-dual-share',
                protocolVersion: input.manifest.protocolVersion,
            },
            complainantRosterEntry.transportPublicKey,
            resolutionPayload.revealedEphemeralPrivateKey,
        );
        if (resolution.valid !== true || resolution.plaintext === undefined) {
            throw new InvalidPayloadError(
                `Complaint resolution failed verification for complainant ${complaint.participantIndex} against dealer ${complaint.dealerIndex}`,
            );
        }

        const decryptedShare = decodePedersenShareEnvelope(
            resolution.plaintext,
            complaint.participantIndex,
            'Complaint resolution',
        );
        const dealerCommitments = pedersenCommitmentMap.get(
            complaint.dealerIndex,
        );
        if (input.protocol === 'gjkr') {
            if (dealerCommitments === undefined) {
                throw new InvalidPayloadError(
                    `Missing Pedersen commitments for dealer ${complaint.dealerIndex}`,
                );
            }
            if (
                !verifyPedersenShare(
                    decryptedShare,
                    {
                        commitments: dealerCommitments,
                    },
                    group,
                )
            ) {
                throw new InvalidPayloadError(
                    `Complaint resolution share failed Pedersen verification for dealer ${complaint.dealerIndex} and complainant ${complaint.participantIndex}`,
                );
            }
        } else if (complaint.reason === 'pedersen-failure') {
            throw new InvalidPayloadError(
                'Joint-Feldman transcripts cannot resolve Pedersen-failure complaints',
            );
        }
    }

    for (const resolutionPayload of complaintResolutionPayloads) {
        if (
            !allowedParticipants.has(resolutionPayload.participantIndex) ||
            !allowedParticipants.has(resolutionPayload.dealerIndex) ||
            !allowedParticipants.has(resolutionPayload.complainantIndex)
        ) {
            throw new InvalidPayloadError(
                `Complaint resolution participants must belong to the active DKG set for phase ${resolutionPayload.phase}`,
            );
        }

        const key = complaintResolutionKey(
            resolutionPayload.complainantIndex,
            resolutionPayload.dealerIndex,
            resolutionPayload.envelopeId,
        );
        if (!usedResolutionKeys.has(key)) {
            throw new InvalidPayloadError(
                `Complaint resolution for envelope ${resolutionPayload.envelopeId} does not match any complaint`,
            );
        }
    }

    return acceptedComplaints;
};
