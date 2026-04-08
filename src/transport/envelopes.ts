import { getWebCrypto, hkdfSha256, randomBytes } from '../core/index.js';
import {
    bytesToHex,
    encodeForChallenge,
    hexToBytes,
} from '../serialize/index.js';

import {
    deriveTransportSharedSecret,
    exportTransportPrivateKey,
    exportTransportPublicKey,
    generateTransportKeyPair,
    importTransportPrivateKey,
    importTransportPublicKey,
} from './key-agreement.js';
import type { EncryptedEnvelope, EnvelopeContext } from './types.js';

const toBufferSource = (bytes: Uint8Array): ArrayBuffer =>
    Uint8Array.from(bytes).buffer;

const aadBytes = (context: EnvelopeContext): Uint8Array =>
    encodeForChallenge(
        context.sessionId,
        BigInt(context.phase),
        BigInt(context.dealerIndex),
        BigInt(context.recipientIndex),
        context.envelopeId,
        context.payloadType,
        context.protocolVersion,
    );

const hkdfInfo = (context: EnvelopeContext): Uint8Array =>
    encodeForChallenge(
        context.sessionId,
        BigInt(context.phase),
        BigInt(context.dealerIndex),
        BigInt(context.recipientIndex),
        context.envelopeId,
        context.protocolVersion,
    );

const importAesKey = async (keyBytes: Uint8Array): Promise<CryptoKey> =>
    getWebCrypto().subtle.importKey(
        'raw',
        toBufferSource(keyBytes),
        'AES-GCM',
        false,
        ['encrypt', 'decrypt'],
    );

const deriveEnvelopeKey = async (
    sharedSecret: Uint8Array,
    context: EnvelopeContext,
): Promise<CryptoKey> =>
    importAesKey(
        await hkdfSha256(
            sharedSecret,
            new TextEncoder().encode(context.rosterHash),
            hkdfInfo(context),
            32,
        ),
    );

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
    recipientPublicKeyHex: string,
    context: EnvelopeContext,
): Promise<{
    readonly envelope: EncryptedEnvelope;
    readonly ephemeralPrivateKey: string;
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
                additionalData: toBufferSource(aadBytes(context)),
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
 * @param recipientPrivateKeyHex Recipient transport private key.
 * @returns Decrypted plaintext bytes.
 */
export const decryptEnvelope = async (
    envelope: EncryptedEnvelope,
    recipientPrivateKey: CryptoKey | string,
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
                additionalData: toBufferSource(aadBytes(envelope)),
            },
            key,
            toBufferSource(hexToBytes(envelope.ciphertext)),
        ),
    );
};
