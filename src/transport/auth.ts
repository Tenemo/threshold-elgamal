/**
 * Ed25519 authentication-key and signature helpers.
 *
 * Every published protocol payload is signed through this layer, either
 * directly or via the higher-level protocol builders.
 */
import { bytesToHex, hexToBytes, toBufferSource } from '../core/bytes';
import { getWebCrypto } from '../core/index';

import type { EncodedAuthPublicKey } from './types';

/** Options controlling authentication-key generation. */
type GenerateAuthKeyPairOptions = {
    /** Whether the generated private key should be extractable. Defaults to `false`. */
    readonly extractable?: boolean;
};

/**
 * Generates a fresh per-ceremony authentication key pair.
 *
 * Trustees use this key pair to sign every public payload they publish during
 * setup, DKG, voting, and tally publication.
 */
export const generateAuthKeyPair = async (
    options: GenerateAuthKeyPairOptions = {},
): Promise<CryptoKeyPair> =>
    getWebCrypto().subtle.generateKey(
        {
            name: 'Ed25519',
        },
        options.extractable ?? false,
        ['sign', 'verify'],
    );

/**
 * Exports an authentication public key as SPKI hex so it can be published in a
 * registration payload and later imported by verifiers.
 */
export const exportAuthPublicKey = async (
    publicKey: CryptoKey,
): Promise<EncodedAuthPublicKey> =>
    bytesToHex(
        new Uint8Array(
            await getWebCrypto().subtle.exportKey('spki', publicKey),
        ),
    ) as EncodedAuthPublicKey;

/**
 * Imports an authentication public key from the canonical published SPKI
 * encoding.
 */
export const importAuthPublicKey = async (
    spkiHex: EncodedAuthPublicKey,
): Promise<CryptoKey> =>
    getWebCrypto().subtle.importKey(
        'spki',
        toBufferSource(hexToBytes(spkiHex)),
        {
            name: 'Ed25519',
        },
        true,
        ['verify'],
    );

/**
 * Signs canonical payload bytes with an authentication private key.
 *
 * Protocol builders call this after they have frozen the payload shape and
 * canonical serialization.
 */
export const signPayloadBytes = async (
    privateKey: CryptoKey,
    payloadBytes: Uint8Array,
): Promise<string> =>
    bytesToHex(
        new Uint8Array(
            await getWebCrypto().subtle.sign(
                'Ed25519',
                privateKey,
                toBufferSource(payloadBytes),
            ),
        ),
    );

/**
 * Verifies canonical payload bytes against an authentication signature.
 *
 * Signature verification for published board payloads ultimately routes
 * through this helper.
 */
export const verifyPayloadSignature = async (
    publicKey: CryptoKey,
    payloadBytes: Uint8Array,
    signatureHex: string,
): Promise<boolean> =>
    getWebCrypto().subtle.verify(
        'Ed25519',
        publicKey,
        toBufferSource(hexToBytes(signatureHex)),
        toBufferSource(payloadBytes),
    );
