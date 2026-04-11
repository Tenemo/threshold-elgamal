import { ed25519 } from '@noble/curves/ed25519.js';

import { canonicalUnsignedPayloadBytes } from '../protocol/payloads.js';
import type { RegistrationPayload, SignedPayload } from '../protocol/types.js';
import { hexToBytes } from '../serialize/index.js';

import type { DKGError } from './types.js';

const ED25519_SPKI_PREFIX = Uint8Array.from([
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

const sameBytes = (left: Uint8Array, right: Uint8Array): boolean => {
    if (left.length !== right.length) {
        return false;
    }

    for (let index = 0; index < left.length; index += 1) {
        if (left[index] !== right[index]) {
            return false;
        }
    }

    return true;
};

const parseRegisteredAuthPublicKey = (
    authPublicKey: RegistrationPayload['authPublicKey'],
): Uint8Array => {
    const spkiBytes = hexToBytes(authPublicKey);

    if (
        spkiBytes.length !== ED25519_SPKI_PREFIX.length + 32 ||
        !sameBytes(
            spkiBytes.slice(0, ED25519_SPKI_PREFIX.length),
            ED25519_SPKI_PREFIX,
        )
    ) {
        throw new Error('Invalid auth public key encoding');
    }

    return spkiBytes.slice(ED25519_SPKI_PREFIX.length);
};

const verifyReducerSignature = (
    signedPayload: SignedPayload,
    publicKey: Uint8Array,
): boolean => {
    try {
        return ed25519.verify(
            hexToBytes(signedPayload.signature),
            canonicalUnsignedPayloadBytes(signedPayload.payload),
            publicKey,
        );
    } catch {
        return false;
    }
};

const registrationMap = (
    transcript: readonly SignedPayload[],
): ReadonlyMap<number, RegistrationPayload> => {
    const registrations = new Map<number, RegistrationPayload>();

    for (const entry of transcript) {
        if (entry.payload.messageType === 'registration') {
            registrations.set(entry.payload.participantIndex, entry.payload);
        }
    }

    return registrations;
};

const payloadSignatureError = (signedPayload: SignedPayload): DKGError => ({
    code: 'signature-invalid',
    message: `Payload signature failed verification for participant ${signedPayload.payload.participantIndex} (${signedPayload.payload.messageType})`,
});

const verifyPayloadAgainstAuthKey = (
    signedPayload: SignedPayload,
    authPublicKey: RegistrationPayload['authPublicKey'],
): DKGError | null => {
    try {
        const publicKey = parseRegisteredAuthPublicKey(authPublicKey);
        if (!verifyReducerSignature(signedPayload, publicKey)) {
            return payloadSignatureError(signedPayload);
        }

        return null;
    } catch {
        return payloadSignatureError(signedPayload);
    }
};

export const validateAuthenticatedPayload = (
    transcript: readonly SignedPayload[],
    signedPayload: SignedPayload,
): DKGError | null => {
    if (signedPayload.payload.messageType === 'registration') {
        try {
            const publicKey = parseRegisteredAuthPublicKey(
                signedPayload.payload.authPublicKey,
            );

            if (!verifyReducerSignature(signedPayload, publicKey)) {
                return {
                    code: 'signature-invalid',
                    message: `Registration signature failed verification for participant ${signedPayload.payload.participantIndex}`,
                };
            }

            return null;
        } catch {
            return {
                code: 'signature-invalid',
                message: `Registration signature failed verification for participant ${signedPayload.payload.participantIndex}`,
            };
        }
    }

    const registrations = registrationMap(transcript);
    const registration = registrations.get(
        signedPayload.payload.participantIndex,
    );
    if (registration === undefined) {
        return {
            code: 'registration-required',
            message: `Participant ${signedPayload.payload.participantIndex} must register before submitting ${signedPayload.payload.messageType}`,
        };
    }

    return verifyPayloadAgainstAuthKey(
        signedPayload,
        registration.authPublicKey,
    );
};
