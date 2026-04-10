import { p256 } from '@noble/curves/nist.js';

import { canonicalUnsignedPayloadBytes } from '../protocol/payloads.js';
import type { RegistrationPayload, SignedPayload } from '../protocol/types.js';
import { hexToBytes } from '../serialize/index.js';

import type { DKGError } from './types.js';

const P256_SPKI_PREFIX = Uint8Array.from([
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
    0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
    0x42, 0x00,
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
        spkiBytes.length !== P256_SPKI_PREFIX.length + 65 ||
        !sameBytes(
            spkiBytes.slice(0, P256_SPKI_PREFIX.length),
            P256_SPKI_PREFIX,
        )
    ) {
        throw new Error('Invalid auth public key encoding');
    }

    const publicKey = spkiBytes.slice(P256_SPKI_PREFIX.length);
    if (publicKey[0] !== 0x04) {
        throw new Error('Invalid auth public key encoding');
    }

    return publicKey;
};

const verifyReducerSignature = (
    signedPayload: SignedPayload,
    publicKey: Uint8Array,
): boolean => {
    try {
        return p256.verify(
            hexToBytes(signedPayload.signature),
            canonicalUnsignedPayloadBytes(signedPayload.payload),
            publicKey,
            {
                lowS: false,
            },
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

    if (signedPayload.payload.messageType === 'manifest-publication') {
        const registration = registrationMap(transcript).get(
            signedPayload.payload.participantIndex,
        );
        if (registration === undefined) {
            return null;
        }

        try {
            const publicKey = parseRegisteredAuthPublicKey(
                registration.authPublicKey,
            );
            if (!verifyReducerSignature(signedPayload, publicKey)) {
                return {
                    code: 'signature-invalid',
                    message: `Payload signature failed verification for participant ${signedPayload.payload.participantIndex} (${signedPayload.payload.messageType})`,
                };
            }

            return null;
        } catch {
            return {
                code: 'signature-invalid',
                message: `Payload signature failed verification for participant ${signedPayload.payload.participantIndex} (${signedPayload.payload.messageType})`,
            };
        }
    }

    const registration = registrationMap(transcript).get(
        signedPayload.payload.participantIndex,
    );
    if (registration === undefined) {
        return {
            code: 'registration-required',
            message: `Participant ${signedPayload.payload.participantIndex} must register before submitting ${signedPayload.payload.messageType}`,
        };
    }

    try {
        const publicKey = parseRegisteredAuthPublicKey(
            registration.authPublicKey,
        );
        if (!verifyReducerSignature(signedPayload, publicKey)) {
            return {
                code: 'signature-invalid',
                message: `Payload signature failed verification for participant ${signedPayload.payload.participantIndex} (${signedPayload.payload.messageType})`,
            };
        }

        return null;
    } catch {
        return {
            code: 'signature-invalid',
            message: `Payload signature failed verification for participant ${signedPayload.payload.participantIndex} (${signedPayload.payload.messageType})`,
        };
    }
};
