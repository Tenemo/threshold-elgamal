import {
    InvalidPayloadError,
    assertValidParticipantIndex,
    sha256,
    utf8ToBytes,
} from '../core/index';
import { bytesToHex } from '../serialize/index';
import { importAuthPublicKey, verifyPayloadSignature } from '../transport/auth';
import { assertSupportedTransportPublicKeyEncoding } from '../transport/key-agreement';
import type {
    EncodedAuthPublicKey,
    EncodedTransportPublicKey,
} from '../transport/types';

import { canonicalizeJson } from './canonical-json';
import { assertSupportedProtocolVersion } from './manifest';
import { signedProtocolPayloadBytes } from './payloads';
import type { RegistrationPayload, SignedPayload } from './types';

/** Roster entry used for deterministic roster hashing. */
export type RosterEntry = {
    readonly participantIndex: number;
    readonly authPublicKey: EncodedAuthPublicKey;
    readonly transportPublicKey: EncodedTransportPublicKey;
};

/** Verified protocol-signature result with the frozen registration roster. */
export type VerifiedProtocolSignatures = {
    readonly participantCount: number;
    readonly registrations: readonly SignedPayload<RegistrationPayload>[];
    readonly rosterEntries: readonly RosterEntry[];
    readonly rosterHash: string;
};

const compareRosterEntries = (
    left: RosterEntry,
    right: RosterEntry,
): number => {
    if (left.participantIndex !== right.participantIndex) {
        return left.participantIndex - right.participantIndex;
    }

    if (left.authPublicKey !== right.authPublicKey) {
        return left.authPublicKey < right.authPublicKey ? -1 : 1;
    }

    return left.transportPublicKey < right.transportPublicKey ? -1 : 1;
};

const assertNonEmptyHex = (value: string, label: string): void => {
    if (value.trim() === '') {
        throw new InvalidPayloadError(`${label} must be a non-empty string`);
    }
};

/**
 * Canonically serializes a frozen roster view.
 *
 * @param rosterEntries Deterministic roster entries.
 * @returns Canonical JSON roster string.
 */
const canonicalizeRosterEntries = (
    rosterEntries: readonly RosterEntry[],
): string => {
    const authKeyOwners = new Map<EncodedAuthPublicKey, number>();
    const transportKeyOwners = new Map<EncodedTransportPublicKey, number>();

    for (const entry of [...rosterEntries].sort(compareRosterEntries)) {
        assertNonEmptyHex(entry.authPublicKey, 'Roster auth public key');
        assertSupportedTransportPublicKeyEncoding(
            entry.transportPublicKey,
            'Roster transport public key',
        );

        const authKeyOwner = authKeyOwners.get(entry.authPublicKey);
        if (authKeyOwner !== undefined) {
            throw new InvalidPayloadError(
                `Duplicate roster auth public key for participants ${authKeyOwner} and ${entry.participantIndex}`,
            );
        }
        authKeyOwners.set(entry.authPublicKey, entry.participantIndex);

        const transportKeyOwner = transportKeyOwners.get(
            entry.transportPublicKey,
        );
        if (transportKeyOwner !== undefined) {
            throw new InvalidPayloadError(
                `Duplicate roster transport public key for participants ${transportKeyOwner} and ${entry.participantIndex}`,
            );
        }
        transportKeyOwners.set(
            entry.transportPublicKey,
            entry.participantIndex,
        );
    }

    return canonicalizeJson(
        [...rosterEntries].sort(compareRosterEntries).map((entry) => ({
            participantIndex: entry.participantIndex,
            authPublicKey: entry.authPublicKey,
            transportPublicKey: entry.transportPublicKey,
        })),
    );
};

/**
 * Hashes a deterministic roster view with SHA-256.
 *
 * @param rosterEntries Deterministic roster entries.
 * @returns Lowercase hexadecimal roster hash.
 */
export const hashRosterEntries = async (
    rosterEntries: readonly RosterEntry[],
): Promise<string> =>
    bytesToHex(
        await sha256(utf8ToBytes(canonicalizeRosterEntries(rosterEntries))),
    );

const assertUniqueParticipantIndices = (
    payloads: readonly SignedPayload[],
    participantCount?: number,
): readonly number[] => {
    const seen = new Set<number>();
    const indices: number[] = [];
    for (const payload of payloads) {
        const participantIndex = payload.payload.participantIndex;
        assertValidParticipantIndex(
            participantIndex,
            participantCount ?? Number.MAX_SAFE_INTEGER,
        );
        if (seen.has(participantIndex)) {
            throw new InvalidPayloadError(
                `Duplicate registration for participant ${participantIndex}`,
            );
        }
        seen.add(participantIndex);
        indices.push(participantIndex);
    }

    indices.sort((left, right) => left - right);
    for (let offset = 0; offset < indices.length; offset += 1) {
        const expectedIndex = offset + 1;
        if (indices[offset] !== expectedIndex) {
            throw new InvalidPayloadError(
                `Registration roster must use contiguous participant indices 1..n (missing ${expectedIndex})`,
            );
        }
    }

    return indices;
};

const registrationKey = (payload: RegistrationPayload): RosterEntry => ({
    participantIndex: payload.participantIndex,
    authPublicKey: payload.authPublicKey,
    transportPublicKey: payload.transportPublicKey,
});

/**
 * Verifies protocol payload signatures against the registration roster carried
 * in the transcript.
 *
 * Registration signatures are verified against the auth key embedded in the
 * same registration payload. Every later payload is verified against the
 * registered auth key for its participant index.
 *
 * @param signedPayloads Signed protocol payloads.
 * @param participantCount Optional expected participant count.
 * @returns Verified registration roster and derived roster hash.
 */
export const verifySignedProtocolPayloads = async (
    signedPayloads: readonly SignedPayload[],
    participantCount?: number,
): Promise<VerifiedProtocolSignatures> => {
    const registrations = signedPayloads.filter(
        (payload): payload is SignedPayload<RegistrationPayload> =>
            payload.payload.messageType === 'registration',
    );

    if (registrations.length === 0) {
        throw new InvalidPayloadError(
            'Protocol transcript requires at least one registration payload',
        );
    }

    const registrationIndices = assertUniqueParticipantIndices(
        registrations,
        participantCount,
    );

    if (
        participantCount !== undefined &&
        registrations.length !== participantCount
    ) {
        throw new InvalidPayloadError(
            `Expected ${participantCount} registration payloads, received ${registrations.length}`,
        );
    }

    const rosterEntries = registrations.map((registration) =>
        registrationKey(registration.payload),
    );
    canonicalizeRosterEntries(rosterEntries);

    const authKeyMap = new Map<number, CryptoKey>();
    for (const registration of registrations) {
        assertNonEmptyHex(
            registration.payload.authPublicKey,
            'Registration auth public key',
        );
        assertNonEmptyHex(
            registration.payload.transportPublicKey,
            'Registration transport public key',
        );
        assertSupportedTransportPublicKeyEncoding(
            registration.payload.transportPublicKey,
            'Registration transport public key',
        );

        assertSupportedProtocolVersion(
            registration.payload.protocolVersion,
            'Protocol payload version',
        );
        const publicKey = await importAuthPublicKey(
            registration.payload.authPublicKey,
        );
        const valid = await verifyPayloadSignature(
            publicKey,
            signedProtocolPayloadBytes(registration.payload),
            registration.signature,
        );

        if (!valid) {
            throw new InvalidPayloadError(
                `Registration signature failed verification for participant ${registration.payload.participantIndex}`,
            );
        }

        authKeyMap.set(registration.payload.participantIndex, publicKey);
    }

    for (const signedPayload of signedPayloads) {
        if (signedPayload.payload.messageType === 'registration') {
            continue;
        }

        const publicKey = authKeyMap.get(
            signedPayload.payload.participantIndex,
        );
        if (publicKey === undefined) {
            throw new InvalidPayloadError(
                `Missing registration for participant ${signedPayload.payload.participantIndex}`,
            );
        }

        assertSupportedProtocolVersion(
            signedPayload.payload.protocolVersion,
            'Protocol payload version',
        );
        const valid = await verifyPayloadSignature(
            publicKey,
            signedProtocolPayloadBytes(signedPayload.payload),
            signedPayload.signature,
        );
        if (!valid) {
            throw new InvalidPayloadError(
                `Payload signature failed verification for participant ${signedPayload.payload.participantIndex} (${signedPayload.payload.messageType})`,
            );
        }
    }

    const sortedRosterEntries = [...rosterEntries].sort(compareRosterEntries);
    const rosterHash = await hashRosterEntries(sortedRosterEntries);

    for (const registration of registrations) {
        if (registration.payload.rosterHash !== rosterHash) {
            throw new InvalidPayloadError(
                `Registration roster hash mismatch for participant ${registration.payload.participantIndex}`,
            );
        }
    }

    return {
        participantCount: registrationIndices.length,
        registrations,
        rosterEntries: sortedRosterEntries,
        rosterHash,
    };
};
