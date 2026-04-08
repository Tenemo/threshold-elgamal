import { describe, expect, it } from 'vitest';

import {
    assertNonZeroSharedSecret,
    decryptEnvelope,
    encryptEnvelope,
    exportAuthPublicKey,
    exportTransportPrivateKey,
    exportTransportPublicKey,
    generateAuthKeyPair,
    generateTransportKeyPair,
    importAuthPublicKey,
    resolveDealerChallenge,
    signPayloadBytes,
    verifyComplaintPrecondition,
    verifyPayloadSignature,
} from '#transport';

describe('transport and authentication', () => {
    it('signs and verifies payload bytes with P-256 authentication keys', async () => {
        const auth = await generateAuthKeyPair();
        const publicKeyHex = await exportAuthPublicKey(auth.publicKey);
        const importedPublicKey = await importAuthPublicKey(publicKeyHex);
        const payload = new TextEncoder().encode('canonical-payload');
        const signature = await signPayloadBytes(auth.privateKey, payload);

        await expect(
            verifyPayloadSignature(importedPublicKey, payload, signature),
        ).resolves.toBe(true);
        await expect(
            verifyPayloadSignature(
                importedPublicKey,
                new TextEncoder().encode('other-payload'),
                signature,
            ),
        ).resolves.toBe(false);
    });

    it('encrypts, decrypts, and resolves envelope complaints', async () => {
        const recipient = await generateTransportKeyPair();
        const recipientPublicKey = await exportTransportPublicKey(
            recipient.publicKey,
        );
        const recipientPrivateKey = await exportTransportPrivateKey(
            recipient.privateKey,
        );
        const plaintext = new TextEncoder().encode('share-pair');
        const { envelope, ephemeralPrivateKey } = await encryptEnvelope(
            plaintext,
            recipientPublicKey,
            {
                sessionId: 'session-1',
                rosterHash: 'roster-1',
                phase: 1,
                dealerIndex: 1,
                recipientIndex: 2,
                envelopeId: 'envelope-1',
                payloadType: 'encrypted-dual-share',
                protocolVersion: 'v2',
                suite: recipient.suite,
            },
        );

        await expect(
            decryptEnvelope(envelope, recipientPrivateKey),
        ).resolves.toEqual(plaintext);
        await expect(
            verifyComplaintPrecondition(
                recipientPrivateKey,
                recipientPublicKey,
                recipient.suite,
            ),
        ).resolves.toBe(true);

        const resolution = await resolveDealerChallenge(
            envelope,
            recipientPrivateKey,
            ephemeralPrivateKey,
        );

        expect(resolution.valid).toBe(true);
        expect(resolution.fault).toBe('complainant');
        expect(resolution.plaintext).toEqual(plaintext);

        const wrongEphemeral = await generateTransportKeyPair(recipient.suite);
        const wrongEphemeralPrivateKey = await exportTransportPrivateKey(
            wrongEphemeral.privateKey,
        );

        await expect(
            resolveDealerChallenge(
                envelope,
                recipientPrivateKey,
                wrongEphemeralPrivateKey,
            ),
        ).resolves.toEqual({
            valid: false,
            fault: 'dealer',
        });
    });

    it('rejects all-zero shared secrets', () => {
        expect(() => assertNonZeroSharedSecret(new Uint8Array(32))).toThrow();
    });
});
