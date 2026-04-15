import { toBufferSource } from '../core/bytes';
import { getWebCrypto } from '../core/index';
import { hexToBytes } from '../serialize/encoding';

import { deriveEnvelopeKey, encodeEnvelopeContext } from './envelopes';
import {
    deriveTransportSharedSecret,
    importTransportPrivateKey,
    importTransportPublicKey,
    verifyLocalTransportKey,
} from './key-agreement';
import type {
    EncodedTransportPrivateKey,
    EncodedTransportPublicKey,
    EncryptedEnvelope,
} from './types';

type ComplaintResolution = {
    readonly valid: boolean;
    readonly fault: 'dealer' | 'complainant';
    readonly plaintext?: Uint8Array;
};

const decryptEnvelopeFromSharedSecret = async (
    envelope: EncryptedEnvelope,
    sharedSecret: Uint8Array,
): Promise<Uint8Array> => {
    const key = await deriveEnvelopeKey(sharedSecret, envelope, ['decrypt']);

    return new Uint8Array(
        await getWebCrypto().subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: toBufferSource(hexToBytes(envelope.iv)),
                additionalData: toBufferSource(encodeEnvelopeContext(envelope)),
            },
            key,
            toBufferSource(hexToBytes(envelope.ciphertext)),
        ),
    );
};

/**
 * Resolves a dealer challenge using only public transcript material plus the
 * dealer-revealed sender-ephemeral private key.
 *
 * @param envelope Committed encrypted envelope.
 * @param recipientPublicKeyHex Registered recipient transport public key.
 * @param revealedEphemeralPrivateKeyHex Revealed sender-ephemeral private key.
 * @returns Complaint resolution result.
 */
export const resolveDealerChallengeFromPublicKey = async (
    envelope: EncryptedEnvelope,
    recipientPublicKeyHex: EncodedTransportPublicKey,
    revealedEphemeralPrivateKeyHex: EncodedTransportPrivateKey,
): Promise<ComplaintResolution> => {
    const ephemeralKeyMatches = await verifyLocalTransportKey(
        revealedEphemeralPrivateKeyHex,
        envelope.ephemeralPublicKey,
    );

    if (!ephemeralKeyMatches) {
        return {
            valid: false,
            fault: 'dealer',
        };
    }

    try {
        const revealedPrivateKey = await importTransportPrivateKey(
            revealedEphemeralPrivateKeyHex,
        );
        const recipientPublicKey = await importTransportPublicKey(
            recipientPublicKeyHex,
        );
        const sharedSecret = await deriveTransportSharedSecret(
            revealedPrivateKey,
            recipientPublicKey,
        );

        return {
            valid: true,
            fault: 'complainant',
            plaintext: await decryptEnvelopeFromSharedSecret(
                envelope,
                sharedSecret,
            ),
        };
    } catch {
        return {
            valid: false,
            fault: 'dealer',
        };
    }
};
