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
    resolveDealerChallenge,
    signPayloadBytes,
    verifyComplaintPrecondition,
    verifyPayloadSignature,
} from '#transport';
import { exportTransportPrivateKey } from '#transport-advanced';

const corruptHexTailByte = (value: string): string => {
    const lastByte = Number.parseInt(value.slice(-2), 16);
    const corruptedByte = (lastByte ^ 0x01).toString(16).padStart(2, '0');
    return `${value.slice(0, -2)}${corruptedByte}`;
};

describe('transport and authentication', () => {
    it('signs and verifies payload bytes with P-256 authentication keys', async () => {
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

    it('encrypts, decrypts, and resolves envelope complaints', async () => {
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
                suite: recipient.suite,
            },
        );

        await expect(
            decryptEnvelope(envelope, recipient.privateKey),
        ).resolves.toEqual(plaintext);
        await expect(
            verifyComplaintPrecondition(
                recipient.privateKey,
                recipientPublicKey,
                recipient.suite,
            ),
        ).resolves.toBe(true);

        const resolution = await resolveDealerChallenge(
            envelope,
            recipient.privateKey,
            ephemeralPrivateKey,
        );

        expect(resolution.valid).toBe(true);
        expect(resolution.fault).toBe('complainant');
        expect(resolution.plaintext).toEqual(plaintext);

        const wrongEphemeral = await generateTransportKeyPair({
            suite: recipient.suite,
            extractable: true,
        });
        const wrongEphemeralPrivateKey = await exportTransportPrivateKey(
            wrongEphemeral.privateKey,
        );

        await expect(
            resolveDealerChallenge(
                envelope,
                recipient.privateKey,
                wrongEphemeralPrivateKey,
            ),
        ).resolves.toEqual({
            valid: false,
            fault: 'dealer',
        });
    });

    it('verifies complaint preconditions for non-extractable P-256 recipient keys', async () => {
        const recipient = await generateTransportKeyPair({
            suite: 'P-256',
        });
        const recipientPublicKey = await exportTransportPublicKey(
            recipient.publicKey,
        );

        await expect(
            verifyComplaintPrecondition(
                recipient.privateKey,
                recipientPublicKey,
                'P-256',
            ),
        ).resolves.toBe(true);
    });

    it('verifies complaint preconditions for exported P-256 recipient keys', async () => {
        const recipient = await generateTransportKeyPair({
            suite: 'P-256',
            extractable: true,
        });
        const recipientPublicKey = await exportTransportPublicKey(
            recipient.publicKey,
        );
        const recipientPrivateKey = await exportTransportPrivateKey(
            recipient.privateKey,
        );

        await expect(
            verifyComplaintPrecondition(
                recipientPrivateKey,
                recipientPublicKey,
                'P-256',
            ),
        ).resolves.toBe(true);
    });

    it('resolves P-256 complaint challenges without exporting the recipient key', async () => {
        const recipient = await generateTransportKeyPair({
            suite: 'P-256',
        });
        const recipientPublicKey = await exportTransportPublicKey(
            recipient.publicKey,
        );
        const plaintext = new TextEncoder().encode('share-pair');
        const { envelope, ephemeralPrivateKey } = await encryptEnvelope(
            plaintext,
            recipientPublicKey,
            {
                sessionId: 'session-p256',
                rosterHash: 'roster-p256',
                phase: 1,
                dealerIndex: 1,
                recipientIndex: 2,
                envelopeId: 'envelope-p256',
                payloadType: 'encrypted-dual-share',
                protocolVersion: 'v1',
                suite: 'P-256',
            },
        );

        await expect(
            resolveDealerChallenge(
                envelope,
                recipient.privateKey,
                ephemeralPrivateKey,
            ),
        ).resolves.toEqual({
            valid: true,
            fault: 'complainant',
            plaintext,
        });
    });

    it('treats malformed P-256 complaint keys as dealer faults instead of throwing', async () => {
        const recipient = await generateTransportKeyPair({
            suite: 'P-256',
        });
        const recipientPublicKey = await exportTransportPublicKey(
            recipient.publicKey,
        );
        const plaintext = new TextEncoder().encode('share-pair');
        const { envelope, ephemeralPrivateKey } = await encryptEnvelope(
            plaintext,
            recipientPublicKey,
            {
                sessionId: 'session-p256-malformed',
                rosterHash: 'roster-p256-malformed',
                phase: 1,
                dealerIndex: 1,
                recipientIndex: 2,
                envelopeId: 'envelope-p256-malformed',
                payloadType: 'encrypted-dual-share',
                protocolVersion: 'v1',
                suite: 'P-256',
            },
        );

        await expect(
            resolveDealerChallenge(
                {
                    ...envelope,
                    ephemeralPublicKey: corruptHexTailByte(
                        envelope.ephemeralPublicKey,
                    ) as typeof envelope.ephemeralPublicKey,
                },
                recipient.privateKey,
                ephemeralPrivateKey,
            ),
        ).resolves.toEqual({
            valid: false,
            fault: 'dealer',
        });
    });

    it('rejects garbled transport inputs and mismatched complaint preconditions', async () => {
        const recipient = await generateTransportKeyPair();
        const otherRecipient = await generateTransportKeyPair();
        const recipientPublicKey = await exportTransportPublicKey(
            recipient.publicKey,
        );
        const otherRecipientPublicKey = await exportTransportPublicKey(
            otherRecipient.publicKey,
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
                suite: recipient.suite,
            },
        );

        await expect(
            verifyComplaintPrecondition(
                recipient.privateKey,
                otherRecipientPublicKey,
                recipient.suite,
            ),
        ).resolves.toBe(false);
        await expect(
            decryptEnvelope(
                { ...envelope, iv: corruptHexTailByte(envelope.iv) },
                recipient.privateKey,
            ),
        ).rejects.toThrow();
        await expect(
            resolveDealerChallenge(
                {
                    ...envelope,
                    ephemeralPublicKey: corruptHexTailByte(
                        envelope.ephemeralPublicKey,
                    ) as typeof envelope.ephemeralPublicKey,
                },
                recipient.privateKey,
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
        await expect(
            decryptEnvelope(
                {
                    ...envelope,
                    suite: recipient.suite === 'P-256' ? 'X25519' : 'P-256',
                },
                recipient.privateKey,
            ),
        ).rejects.toThrow();
    });

    it('rejects all-zero shared secrets', () => {
        expect(() => assertNonZeroSharedSecret(new Uint8Array(32))).toThrow();
    });
});
