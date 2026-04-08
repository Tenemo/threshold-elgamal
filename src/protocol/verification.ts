import {
    InvalidPayloadError,
    assertValidParticipantIndex,
    sha256,
    utf8ToBytes,
} from '../core/index.js';
import { bytesToHex } from '../serialize/index.js';
import {
    importAuthPublicKey,
    verifyPayloadSignature,
} from '../transport/auth.js';

import { canonicalizeJson } from './canonical-json.js';
import { canonicalUnsignedPayloadBytes } from './payloads.js';
import type { RegistrationPayload, SignedPayload } from './types.js';

/** Roster entry used for deterministic roster hashing. */
export type RosterEntry = {
    readonly participantIndex: number;
    readonly authPublicKey: string;
    readonly transportPublicKey: string;
};

/** Verified protocol-signature result with the frozen registration roster. */
export type VerifiedProtocolSignatures = {
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
export const canonicalizeRosterEntries = (
    rosterEntries: readonly RosterEntry[],
): string =>
    canonicalizeJson(
        [...rosterEntries].sort(compareRosterEntries).map((entry) => ({
            participantIndex: entry.participantIndex,
            authPublicKey: entry.authPublicKey,
            transportPublicKey: entry.transportPublicKey,
        })),
    );

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
): void => {
    const seen = new Set<number>();
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
    }
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

    assertUniqueParticipantIndices(registrations, participantCount);

    if (
        participantCount !== undefined &&
        registrations.length !== participantCount
    ) {
        throw new InvalidPayloadError(
            `Expected ${participantCount} registration payloads, received ${registrations.length}`,
        );
    }

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

        const publicKey = await importAuthPublicKey(
            registration.payload.authPublicKey,
        );
        const valid = await verifyPayloadSignature(
            publicKey,
            canonicalUnsignedPayloadBytes(registration.payload),
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

        const valid = await verifyPayloadSignature(
            publicKey,
            canonicalUnsignedPayloadBytes(signedPayload.payload),
            signedPayload.signature,
        );
        if (!valid) {
            throw new InvalidPayloadError(
                `Payload signature failed verification for participant ${signedPayload.payload.participantIndex} (${signedPayload.payload.messageType})`,
            );
        }
    }

    const rosterEntries = registrations
        .map((registration) => registrationKey(registration.payload))
        .sort(compareRosterEntries);
    const rosterHash = await hashRosterEntries(rosterEntries);

    for (const registration of registrations) {
        if (registration.payload.rosterHash !== rosterHash) {
            throw new InvalidPayloadError(
                `Registration roster hash mismatch for participant ${registration.payload.participantIndex}`,
            );
        }
    }

    return {
        registrations,
        rosterEntries,
        rosterHash,
    };
};
