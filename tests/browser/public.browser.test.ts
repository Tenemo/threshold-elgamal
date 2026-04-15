import { describe, expect, it } from 'vitest';

import {
    decryptEnvelope,
    encryptEnvelope,
    exportTransportPublicKey,
    generateTransportKeyPair,
} from '#root';

describe('browser public surface', () => {
    it('round-trips an encrypted envelope with browser CryptoKeys', async () => {
        const recipient = await generateTransportKeyPair();
        const recipientPublicKey = await exportTransportPublicKey(
            recipient.publicKey,
        );
        const plaintext = new TextEncoder().encode('browser-envelope');
        const { envelope } = await encryptEnvelope(
            plaintext,
            recipientPublicKey,
            {
                sessionId: 'browser-session',
                rosterHash: 'browser-roster',
                phase: 1,
                dealerIndex: 1,
                recipientIndex: 2,
                envelopeId: 'browser-envelope-1',
                payloadType: 'encrypted-dual-share',
                protocolVersion: 'v1',
                suite: 'X25519',
            },
        );
        const decrypted = await decryptEnvelope(envelope, recipient.privateKey);

        expect(new TextDecoder().decode(decrypted)).toBe('browser-envelope');
        expect(envelope.iv).toHaveLength(24);
        expect(envelope.ciphertext).not.toBe('');
    });
});
