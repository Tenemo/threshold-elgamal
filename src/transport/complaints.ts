import { toBufferSource } from '../core/bytes.js';
import { getWebCrypto } from '../core/index.js';
import { hexToBytes } from '../serialize/index.js';

import { deriveEnvelopeKey, encodeEnvelopeContext } from './envelope-crypto.js';
import {
    deriveTransportPublicKey,
    deriveTransportSharedSecret,
    importTransportPrivateKey,
    importTransportPublicKey,
    verifyLocalTransportKey,
} from './key-agreement.js';
import type {
    ComplaintResolution,
    EncryptedEnvelope,
    KeyAgreementSuite,
} from './types.js';

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
 * Verifies that the local recipient transport key still matches the registered
 * public key before filing a transport complaint.
 *
 * @param privateKey Recipient transport private key.
 * @param expectedPublicKeyHex Registered recipient public key.
 * @param suite Transport key-agreement suite.
 * @returns `true` when the local key material matches the registration.
 */
export const verifyComplaintPrecondition = async (
    privateKey: CryptoKey | string,
    expectedPublicKeyHex: string,
    suite: KeyAgreementSuite,
): Promise<boolean> =>
    verifyLocalTransportKey(privateKey, expectedPublicKeyHex, suite);

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
    recipientPublicKeyHex: string,
    revealedEphemeralPrivateKeyHex: string,
): Promise<ComplaintResolution> => {
    const derivedPublicKey = await verifyLocalTransportKey(
        revealedEphemeralPrivateKeyHex,
        envelope.ephemeralPublicKey,
        envelope.suite,
    );

    if (!derivedPublicKey) {
        return {
            valid: false,
            fault: 'dealer',
        };
    }

    const revealedPrivateKey =
        typeof revealedEphemeralPrivateKeyHex === 'string'
            ? await importTransportPrivateKey(
                  revealedEphemeralPrivateKeyHex,
                  envelope.suite,
              )
            : revealedEphemeralPrivateKeyHex;

    try {
        const recipientPublicKey = await importTransportPublicKey(
            recipientPublicKeyHex,
            envelope.suite,
        );
        const sharedSecret = await deriveTransportSharedSecret(
            revealedPrivateKey,
            recipientPublicKey,
            envelope.suite,
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

/**
 * Resolves a dealer challenge by revealing the sender-ephemeral private key.
 *
 * If the revealed private key does not match the committed ephemeral public
 * key, or if the committed ciphertext still fails to decrypt, the dealer is at
 * fault. Successful decryption resolves the complaint in the dealer's favor.
 *
 * @param envelope Committed encrypted envelope.
 * @param recipientPrivateKey Recipient transport private key.
 * @param revealedEphemeralPrivateKeyHex Revealed sender-ephemeral private key.
 * @returns Complaint resolution result.
 */
export const resolveDealerChallenge = async (
    envelope: EncryptedEnvelope,
    recipientPrivateKey: CryptoKey | string,
    revealedEphemeralPrivateKeyHex: string,
): Promise<ComplaintResolution> => {
    const recipientPublicKeyHex = await deriveTransportPublicKey(
        typeof recipientPrivateKey === 'string'
            ? await importTransportPrivateKey(
                  recipientPrivateKey,
                  envelope.suite,
              )
            : recipientPrivateKey,
        envelope.suite,
    );

    return resolveDealerChallengeFromPublicKey(
        envelope,
        recipientPublicKeyHex,
        revealedEphemeralPrivateKeyHex,
    );
};
