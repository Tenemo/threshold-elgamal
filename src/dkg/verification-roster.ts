import { InvalidPayloadError } from '../core/index.js';
import { hashElectionManifest } from '../protocol/manifest.js';
import type {
    ManifestAcceptancePayload,
    ManifestPublicationPayload,
    SignedPayload,
} from '../protocol/types.js';
import {
    verifySignedProtocolPayloads,
    type VerifiedProtocolSignatures,
} from '../protocol/verification.js';

import {
    assertUniqueSlots,
    groupByParticipant,
    requireExactlyOnePayload,
    validateParticipantIndex,
} from './verification-shared.js';

export const verifySignedRoster = async (
    transcript: readonly SignedPayload[],
    participantCount: number,
    expectedRosterHash: string,
): Promise<VerifiedProtocolSignatures> => {
    assertUniqueSlots(transcript);

    const verifiedSignatures = await verifySignedProtocolPayloads(
        transcript,
        participantCount,
    );
    if (verifiedSignatures.rosterHash !== expectedRosterHash) {
        throw new InvalidPayloadError(
            'Registration roster hash does not match the manifest roster hash',
        );
    }

    return verifiedSignatures;
};

export const verifyManifestPublicationPayload = async (
    transcript: readonly SignedPayload[],
    manifestHash: string,
): Promise<void> => {
    const manifestPublication = requireExactlyOnePayload(
        transcript
            .filter(
                (
                    payload,
                ): payload is SignedPayload<ManifestPublicationPayload> =>
                    payload.payload.messageType === 'manifest-publication',
            )
            .map((payload) => payload.payload),
        'Manifest publication',
    );
    if (
        (await hashElectionManifest(manifestPublication.manifest)) !==
        manifestHash
    ) {
        throw new InvalidPayloadError(
            'Manifest publication does not match the verification input manifest',
        );
    }
};

export const verifyManifestAcceptancePayloads = (
    transcript: readonly SignedPayload[],
    participantCount: number,
    expectedRosterHash: string,
    requireUnanimous: boolean,
): readonly number[] => {
    const acceptances = transcript
        .filter(
            (payload): payload is SignedPayload<ManifestAcceptancePayload> =>
                payload.payload.messageType === 'manifest-acceptance',
        )
        .map((payload) => payload.payload);
    const grouped = groupByParticipant(acceptances);

    if (requireUnanimous && grouped.size !== participantCount) {
        throw new InvalidPayloadError(
            `Manifest acceptance requires exactly ${participantCount} participant payloads`,
        );
    }

    for (const [participantIndex, participantPayloads] of grouped.entries()) {
        validateParticipantIndex(
            participantIndex,
            participantCount,
            'Manifest acceptance participant index',
        );
        if (participantPayloads.length !== 1) {
            throw new InvalidPayloadError(
                `Manifest acceptance requires exactly one payload for participant ${participantIndex}`,
            );
        }
    }

    for (const acceptance of acceptances) {
        if (acceptance.rosterHash !== expectedRosterHash) {
            throw new InvalidPayloadError(
                `Manifest acceptance roster hash mismatch for participant ${acceptance.participantIndex}`,
            );
        }
        if (
            acceptance.assignedParticipantIndex !== acceptance.participantIndex
        ) {
            throw new InvalidPayloadError(
                `Participant ${acceptance.participantIndex} accepted a mismatched assigned index`,
            );
        }
    }

    return acceptances
        .map((acceptance) => acceptance.participantIndex)
        .sort((left, right) => left - right);
};
