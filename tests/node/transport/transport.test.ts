import { describe, expect, it } from 'vitest';

import {
    assertNonZeroSharedSecret,
    decryptEnvelope,
    encryptEnvelope,
    exportAuthPublicKey,
    exportTransportPublicKey,
    generateAuthKeyPair,
    generateTransportKeyPair,
    importAuthPublicKey,
    importTransportPublicKey,
    resolveDealerChallengeFromPublicKey,
    signPayloadBytes,
    verifyPayloadSignature,
} from '#transport';

const corruptHexTailByte = (value: string): string => {
    const lastByte = Number.parseInt(value.slice(-2), 16);
    const corruptedByte = (lastByte ^ 0x01).toString(16).padStart(2, '0');
    return `${value.slice(0, -2)}${corruptedByte}`;
};

describe('transport and authentication', () => {
    it('signs and verifies payload bytes with authentication keys', async () => {
        const auth = await generateAuthKeyPair();
        const publicKeyHex = await exportAuthPublicKey(auth.publicKey);
        const importedPublicKey = await importAuthPublicKey(publicKeyHex);
        const payload = new TextEncoder().encode('canonical-payload');
        const signature = await signPayloadBytes(auth.privateKey, payload);

        expect(signature).toHaveLength(128);
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

    it('encrypts, decrypts, and resolves public dealer challenges', async () => {
        const recipient = await generateTransportKeyPair();
        const recipientPublicKey = await exportTransportPublicKey(
            recipient.publicKey,
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
                protocolVersion: 'v1',
                suite: 'X25519',
            },
        );

        await expect(
            decryptEnvelope(envelope, recipient.privateKey),
        ).resolves.toEqual(plaintext);

        const resolution = await resolveDealerChallengeFromPublicKey(
            envelope,
            recipientPublicKey,
            ephemeralPrivateKey,
        );

        expect(resolution.valid).toBe(true);
        expect(resolution.fault).toBe('complainant');
        expect(resolution.plaintext).toEqual(plaintext);
    });

    it('treats malformed exported dealer-challenge keys as dealer faults', async () => {
        const recipient = await generateTransportKeyPair();
        const recipientPublicKey = await exportTransportPublicKey(
            recipient.publicKey,
        );
        const plaintext = new TextEncoder().encode('share-pair');
        const { envelope } = await encryptEnvelope(
            plaintext,
            recipientPublicKey,
            {
                sessionId: 'session-malformed-export',
                rosterHash: 'roster-malformed-export',
                phase: 1,
                dealerIndex: 1,
                recipientIndex: 2,
                envelopeId: 'envelope-malformed-export',
                payloadType: 'encrypted-dual-share',
                protocolVersion: 'v1',
                suite: 'X25519',
            },
        );

        await expect(
            resolveDealerChallengeFromPublicKey(
                envelope,
                recipientPublicKey,
                '00'.repeat(
                    67,
                ) as import('#transport').EncodedTransportPrivateKey,
            ),
        ).resolves.toEqual({
            valid: false,
            fault: 'dealer',
        });
    });

    it('rejects garbled transport inputs and malformed complaint resolutions', async () => {
        const recipient = await generateTransportKeyPair();
        const recipientPublicKey = await exportTransportPublicKey(
            recipient.publicKey,
        );
        const plaintext = new TextEncoder().encode('share-pair');
        const { envelope, ephemeralPrivateKey } = await encryptEnvelope(
            plaintext,
            recipientPublicKey,
            {
                sessionId: 'session-2',
                rosterHash: 'roster-2',
                phase: 1,
                dealerIndex: 1,
                recipientIndex: 2,
                envelopeId: 'envelope-2',
                payloadType: 'encrypted-dual-share',
                protocolVersion: 'v1',
                suite: 'X25519',
            },
        );

        await expect(
            decryptEnvelope(
                { ...envelope, iv: corruptHexTailByte(envelope.iv) },
                recipient.privateKey,
            ),
        ).rejects.toThrow();
        await expect(
            resolveDealerChallengeFromPublicKey(
                {
                    ...envelope,
                    ephemeralPublicKey: corruptHexTailByte(
                        envelope.ephemeralPublicKey,
                    ) as typeof envelope.ephemeralPublicKey,
                },
                recipientPublicKey,
                ephemeralPrivateKey,
            ),
        ).resolves.toEqual({
            valid: false,
            fault: 'dealer',
        });
        await expect(
            decryptEnvelope(
                {
                    ...envelope,
                    payloadType: 'feldman-share-reveal',
                },
                recipient.privateKey,
            ),
        ).rejects.toThrow();
    });

    it('rejects all-zero shared secrets', () => {
        expect(() => assertNonZeroSharedSecret(new Uint8Array(32))).toThrow();
    });

    it('rejects the all-zero X25519 public key before key agreement', async () => {
        await expect(
            importTransportPublicKey(
                '00'.repeat(
                    32,
                ) as import('#transport').EncodedTransportPublicKey,
            ),
        ).rejects.toThrow(
            'Transport public key must not be the all-zero X25519 public key',
        );
    });
});
