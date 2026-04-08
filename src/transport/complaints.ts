import { decryptEnvelope } from './envelopes.js';
import {
    importTransportPrivateKey,
    deriveTransportPublicKey,
} from './key-agreement.js';
import type {
    ComplaintResolution,
    EncryptedEnvelope,
    KeyAgreementSuite,
} from './types.js';

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
        return {
            valid: true,
            fault: 'complainant',
            plaintext: await decryptEnvelope(envelope, recipientPrivateKey),
        };
    } catch {
        return {
            valid: false,
            fault: 'dealer',
        };
    }
};
