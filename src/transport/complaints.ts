import { getWebCrypto, hkdfSha256 } from '../core/index.js';
import { encodeForChallenge, hexToBytes } from '../serialize/index.js';

import {
    deriveTransportSharedSecret,
    importTransportPrivateKey,
    importTransportPublicKey,
    deriveTransportPublicKey,
} from './key-agreement.js';
import type {
    ComplaintResolution,
    EncryptedEnvelope,
    KeyAgreementSuite,
} from './types.js';

const toBufferSource = (bytes: Uint8Array): ArrayBuffer =>
    Uint8Array.from(bytes).buffer;

const aadBytes = (envelope: EncryptedEnvelope): Uint8Array =>
    encodeForChallenge(
        envelope.sessionId,
        BigInt(envelope.phase),
        BigInt(envelope.dealerIndex),
        BigInt(envelope.recipientIndex),
        envelope.envelopeId,
        envelope.payloadType,
        envelope.protocolVersion,
    );

const hkdfInfo = (envelope: EncryptedEnvelope): Uint8Array =>
    encodeForChallenge(
        envelope.sessionId,
        BigInt(envelope.phase),
        BigInt(envelope.dealerIndex),
        BigInt(envelope.recipientIndex),
        envelope.envelopeId,
        envelope.payloadType,
        envelope.protocolVersion,
    );

const importAesKey = async (keyBytes: Uint8Array): Promise<CryptoKey> =>
    getWebCrypto().subtle.importKey(
        'raw',
        toBufferSource(keyBytes),
        'AES-GCM',
        false,
        ['decrypt'],
    );

const deriveEnvelopeKey = async (
    sharedSecret: Uint8Array,
    envelope: EncryptedEnvelope,
): Promise<CryptoKey> =>
    importAesKey(
        await hkdfSha256(
            sharedSecret,
            new TextEncoder().encode(envelope.rosterHash),
            hkdfInfo(envelope),
            32,
        ),
    );

const decryptEnvelopeFromSharedSecret = async (
    envelope: EncryptedEnvelope,
    sharedSecret: Uint8Array,
): Promise<Uint8Array> => {
    const key = await deriveEnvelopeKey(sharedSecret, envelope);

    return new Uint8Array(
        await getWebCrypto().subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: toBufferSource(hexToBytes(envelope.iv)),
                additionalData: toBufferSource(aadBytes(envelope)),
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
): Promise<boolean> => {
    const resolvedPrivateKey =
        typeof privateKey === 'string'
            ? await importTransportPrivateKey(privateKey, suite)
            : privateKey;
    return (
        (await deriveTransportPublicKey(resolvedPrivateKey, suite)) ===
        expectedPublicKeyHex
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
    recipientPublicKeyHex: string,
    revealedEphemeralPrivateKeyHex: string,
): Promise<ComplaintResolution> => {
    const revealedPrivateKey = await importTransportPrivateKey(
        revealedEphemeralPrivateKeyHex,
        envelope.suite,
    );
    const derivedPublicKey = await deriveTransportPublicKey(
        revealedPrivateKey,
        envelope.suite,
    );

    if (derivedPublicKey !== envelope.ephemeralPublicKey) {
        return {
            valid: false,
            fault: 'dealer',
        };
    }

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
    if (typeof recipientPrivateKey !== 'string') {
        return resolveDealerChallengeFromPublicKey(
            envelope,
            await deriveTransportPublicKey(recipientPrivateKey, envelope.suite),
            revealedEphemeralPrivateKeyHex,
        );
    }

    const resolvedPrivateKey = await importTransportPrivateKey(
        recipientPrivateKey,
        envelope.suite,
    );

    return resolveDealerChallengeFromPublicKey(
        envelope,
        await deriveTransportPublicKey(resolvedPrivateKey, envelope.suite),
        revealedEphemeralPrivateKeyHex,
    );
};
