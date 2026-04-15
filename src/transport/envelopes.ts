/**
 * Authenticated sender-ephemeral envelope helpers for dealer-to-recipient
 * transport during DKG share distribution.
 */
import { bytesToHex, hexToBytes, toBufferSource } from '../core/bytes';
import { getWebCrypto, hkdfSha256, randomBytes } from '../core/index';
import { encodeForChallenge } from '../serialize/encoding';

import {
    deriveTransportSharedSecret,
    exportTransportPrivateKey,
    exportTransportPublicKey,
    generateTransportKeyPair,
    importTransportPrivateKey,
    importTransportPublicKey,
} from './key-agreement';
import type {
    EncodedTransportPrivateKey,
    EncodedTransportPublicKey,
    EncryptedEnvelope,
    EnvelopeContext,
} from './types';

const envelopeKeySalt = (rosterHash: string): Uint8Array =>
    new TextEncoder().encode(rosterHash);

export const encodeEnvelopeContext = (context: EnvelopeContext): Uint8Array =>
    encodeForChallenge(
        context.sessionId,
        BigInt(context.phase),
        BigInt(context.dealerIndex),
        BigInt(context.recipientIndex),
        context.envelopeId,
        context.payloadType,
        context.protocolVersion,
        context.suite,
    );

export const deriveEnvelopeKey = async (
    sharedSecret: Uint8Array,
    context: EnvelopeContext,
    usages: KeyUsage[] = ['encrypt', 'decrypt'],
): Promise<CryptoKey> =>
    getWebCrypto().subtle.importKey(
        'raw',
        toBufferSource(
            await hkdfSha256(
                sharedSecret,
                envelopeKeySalt(context.rosterHash),
                encodeEnvelopeContext(context),
                32,
            ),
        ),
        'AES-GCM',
        false,
        usages,
    );

/**
 * Encrypts a payload into a sender-ephemeral authenticated envelope.
 *
 * DKG dealers use this when publishing encrypted Pedersen shares for one
 * recipient. The returned ephemeral private key is retained so complaint
 * resolution can later prove what was sent.
 */
export const encryptEnvelope = async (
    plaintext: Uint8Array,
    recipientPublicKeyHex: EncodedTransportPublicKey,
    context: EnvelopeContext,
): Promise<{
    readonly envelope: EncryptedEnvelope;
    readonly ephemeralPrivateKey: EncodedTransportPrivateKey;
}> => {
    const ephemeral = await generateTransportKeyPair({
        extractable: true,
    });
    const recipientPublicKey = await importTransportPublicKey(
        recipientPublicKeyHex,
    );
    const sharedSecret = await deriveTransportSharedSecret(
        ephemeral.privateKey,
        recipientPublicKey,
    );
    const key = await deriveEnvelopeKey(sharedSecret, context);
    const iv = randomBytes(12);
    const ciphertext = new Uint8Array(
        await getWebCrypto().subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: toBufferSource(iv),
                additionalData: toBufferSource(encodeEnvelopeContext(context)),
            },
            key,
            toBufferSource(plaintext),
        ),
    );

    return {
        envelope: {
            ...context,
            ephemeralPublicKey: await exportTransportPublicKey(
                ephemeral.publicKey,
            ),
            iv: bytesToHex(iv),
            ciphertext: bytesToHex(ciphertext),
        },
        ephemeralPrivateKey: await exportTransportPrivateKey(
            ephemeral.privateKey,
        ),
    };
};

/**
 * Decrypts an authenticated envelope with the recipient transport private key.
 *
 * This is the recipient-side counterpart to {@link encryptEnvelope} and is
 * typically followed by Pedersen share decoding.
 */
export const decryptEnvelope = async (
    envelope: EncryptedEnvelope,
    recipientPrivateKey: CryptoKey | EncodedTransportPrivateKey,
): Promise<Uint8Array> => {
    const resolvedRecipientPrivateKey =
        typeof recipientPrivateKey === 'string'
            ? await importTransportPrivateKey(recipientPrivateKey)
            : recipientPrivateKey;
    const senderPublicKey = await importTransportPublicKey(
        envelope.ephemeralPublicKey,
    );
    const sharedSecret = await deriveTransportSharedSecret(
        resolvedRecipientPrivateKey,
        senderPublicKey,
    );
    const key = await deriveEnvelopeKey(sharedSecret, envelope);

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
