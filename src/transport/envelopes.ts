import { toBufferSource } from '../core/bytes.js';
import { getWebCrypto, randomBytes } from '../core/index.js';
import { bytesToHex, hexToBytes } from '../serialize/index.js';

import { deriveEnvelopeKey, encodeEnvelopeContext } from './envelope-crypto.js';
import {
    deriveTransportSharedSecret,
    exportTransportPrivateKey,
    exportTransportPublicKey,
    generateTransportKeyPair,
    importTransportPrivateKey,
    importTransportPublicKey,
} from './key-agreement.js';
import type {
    EncodedTransportPrivateKey,
    EncodedTransportPublicKey,
    EncryptedEnvelope,
    EnvelopeContext,
} from './types.js';

/**
 * Encrypts a payload into a sender-ephemeral authenticated envelope.
 *
 * @param plaintext Raw payload bytes to encrypt.
 * @param recipientPublicKeyHex Recipient transport public key.
 * @param context Envelope binding context.
 * @returns Envelope plus the sender-ephemeral private key for complaint recovery.
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
        suite: context.suite,
        extractable: true,
    });
    const recipientPublicKey = await importTransportPublicKey(
        recipientPublicKeyHex,
        context.suite,
    );
    const sharedSecret = await deriveTransportSharedSecret(
        ephemeral.privateKey,
        recipientPublicKey,
        context.suite,
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
 * @param envelope Authenticated encrypted envelope.
 * @param recipientPrivateKey Recipient transport private key.
 * @returns Decrypted plaintext bytes.
 */
export const decryptEnvelope = async (
    envelope: EncryptedEnvelope,
    recipientPrivateKey: CryptoKey | EncodedTransportPrivateKey,
): Promise<Uint8Array> => {
    const resolvedRecipientPrivateKey =
        typeof recipientPrivateKey === 'string'
            ? await importTransportPrivateKey(
                  recipientPrivateKey,
                  envelope.suite,
              )
            : recipientPrivateKey;
    const senderPublicKey = await importTransportPublicKey(
        envelope.ephemeralPublicKey,
        envelope.suite,
    );
    const sharedSecret = await deriveTransportSharedSecret(
        resolvedRecipientPrivateKey,
        senderPublicKey,
        envelope.suite,
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
