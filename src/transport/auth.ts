import { getWebCrypto } from '../core/index.js';
import { bytesToHex, hexToBytes } from '../serialize/index.js';

const toBufferSource = (bytes: Uint8Array): ArrayBuffer =>
    Uint8Array.from(bytes).buffer;

/** Options controlling authentication-key generation. */
export type GenerateAuthKeyPairOptions = {
    /** Whether the generated private key should be extractable. Defaults to `false`. */
    readonly extractable?: boolean;
};

/**
 * Generates a fresh per-ceremony ECDSA P-256 authentication key pair.
 *
 * @returns Extractable authentication key pair.
 */
export const generateAuthKeyPair = async (
    options: GenerateAuthKeyPairOptions = {},
): Promise<CryptoKeyPair> =>
    getWebCrypto().subtle.generateKey(
        {
            name: 'ECDSA',
            namedCurve: 'P-256',
        },
        options.extractable ?? false,
        ['sign', 'verify'],
    );

/**
 * Exports an authentication public key as SPKI hex.
 *
 * @param publicKey Authentication public key.
 * @returns Lowercase hexadecimal SPKI bytes.
 */
export const exportAuthPublicKey = async (
    publicKey: CryptoKey,
): Promise<string> =>
    bytesToHex(
        new Uint8Array(
            await getWebCrypto().subtle.exportKey('spki', publicKey),
        ),
    );

/**
 * Imports an authentication public key from SPKI hex.
 *
 * @param spkiHex Lowercase hexadecimal SPKI bytes.
 * @returns Imported public key.
 */
export const importAuthPublicKey = async (
    spkiHex: string,
): Promise<CryptoKey> =>
    getWebCrypto().subtle.importKey(
        'spki',
        toBufferSource(hexToBytes(spkiHex)),
        {
            name: 'ECDSA',
            namedCurve: 'P-256',
        },
        true,
        ['verify'],
    );

/**
 * Signs canonical payload bytes with an authentication private key.
 *
 * @param privateKey Authentication private key.
 * @param payloadBytes Canonical unsigned payload bytes.
 * @returns Lowercase hexadecimal P1363 signature bytes.
 */
export const signPayloadBytes = async (
    privateKey: CryptoKey,
    payloadBytes: Uint8Array,
): Promise<string> =>
    bytesToHex(
        new Uint8Array(
            await getWebCrypto().subtle.sign(
                {
                    name: 'ECDSA',
                    hash: 'SHA-256',
                },
                privateKey,
                toBufferSource(payloadBytes),
            ),
        ),
    );

/**
 * Verifies canonical payload bytes against a P-256 authentication signature.
 *
 * @param publicKey Authentication public key.
 * @param payloadBytes Canonical unsigned payload bytes.
 * @param signatureHex Lowercase hexadecimal P1363 signature bytes.
 * @returns `true` when the signature verifies.
 */
export const verifyPayloadSignature = async (
    publicKey: CryptoKey,
    payloadBytes: Uint8Array,
    signatureHex: string,
): Promise<boolean> =>
    getWebCrypto().subtle.verify(
        {
            name: 'ECDSA',
            hash: 'SHA-256',
        },
        publicKey,
        toBufferSource(hexToBytes(signatureHex)),
        toBufferSource(payloadBytes),
    );
