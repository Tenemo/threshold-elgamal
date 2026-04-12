import { toBufferSource } from '../core/bytes';
import { InvalidPayloadError, getWebCrypto } from '../core/index';
import { bytesToHex, hexToBytes } from '../serialize/index';

import type {
    EncodedTransportPrivateKey,
    EncodedTransportPublicKey,
    TransportKeyPair,
} from './types';

const X25519_BASE_POINT = (() => {
    const bytes = new Uint8Array(32);
    bytes[0] = 9;
    return bytes;
})();
const X25519_PUBLIC_KEY_LENGTH = 32;

const isAllZeroBytes = (bytes: Uint8Array): boolean =>
    bytes.every((value) => value === 0);

const assertValidX25519PublicKeyBytes = (
    publicKeyBytes: Uint8Array,
    label: string,
): void => {
    if (publicKeyBytes.length !== X25519_PUBLIC_KEY_LENGTH) {
        throw new InvalidPayloadError(
            `${label} must be a supported raw X25519 public key`,
        );
    }

    if (isAllZeroBytes(publicKeyBytes)) {
        throw new InvalidPayloadError(
            `${label} must not be the all-zero X25519 public key`,
        );
    }
};

const x25519Algorithm = { name: 'X25519' } as const;

/** Options controlling transport-key generation. */
export type GenerateTransportKeyPairOptions = {
    /** Whether the generated private key should be extractable. Defaults to `false`. */
    readonly extractable?: boolean;
};

/**
 * Rejects all-zero key-agreement secrets.
 *
 * @param sharedSecret Derived shared secret bytes.
 * @throws When the shared secret is all zero.
 */
export const assertNonZeroSharedSecret = (sharedSecret: Uint8Array): void => {
    if (sharedSecret.every((byte) => byte === 0)) {
        throw new InvalidPayloadError(
            'Key agreement produced an all-zero shared secret',
        );
    }
};

/**
 * Generates an X25519 transport key pair.
 *
 * @param options Generation options.
 * @returns Transport key pair tagged with the shipped X25519 suite.
 */
export const generateTransportKeyPair = async (
    options: GenerateTransportKeyPairOptions = {},
): Promise<TransportKeyPair> => {
    const keyPair = await getWebCrypto().subtle.generateKey(
        x25519Algorithm,
        options.extractable ?? false,
        ['deriveBits'],
    );

    return {
        suite: 'X25519',
        privateKey: keyPair.privateKey,
        publicKey: keyPair.publicKey,
    };
};

/**
 * Exports a transport public key as raw lowercase hexadecimal bytes.
 *
 * @param publicKey Transport public key.
 * @returns Lowercase hexadecimal public key bytes.
 */
export const exportTransportPublicKey = async (
    publicKey: CryptoKey,
): Promise<EncodedTransportPublicKey> =>
    bytesToHex(
        new Uint8Array(await getWebCrypto().subtle.exportKey('raw', publicKey)),
    ) as EncodedTransportPublicKey;

/**
 * Exports a transport private key as PKCS#8 lowercase hexadecimal bytes.
 *
 * @param privateKey Transport private key.
 * @returns Lowercase hexadecimal PKCS#8 bytes.
 */
export const exportTransportPrivateKey = async (
    privateKey: CryptoKey,
): Promise<EncodedTransportPrivateKey> =>
    bytesToHex(
        new Uint8Array(
            await getWebCrypto().subtle.exportKey('pkcs8', privateKey),
        ),
    ) as EncodedTransportPrivateKey;

/**
 * Imports a transport public key from raw hexadecimal bytes.
 *
 * @param publicKeyHex Lowercase hexadecimal public key bytes.
 * @returns Imported transport public key.
 */
export const importTransportPublicKey = async (
    publicKeyHex: EncodedTransportPublicKey,
): Promise<CryptoKey> => {
    const publicKeyBytes = hexToBytes(publicKeyHex);
    assertValidX25519PublicKeyBytes(publicKeyBytes, 'Transport public key');

    return getWebCrypto().subtle.importKey(
        'raw',
        toBufferSource(publicKeyBytes),
        x25519Algorithm,
        true,
        [],
    );
};

export const assertSupportedTransportPublicKeyEncoding = (
    publicKeyHex: EncodedTransportPublicKey,
    label = 'Transport public key',
): void => {
    let publicKeyBytes: Uint8Array;

    try {
        publicKeyBytes = hexToBytes(publicKeyHex);
    } catch {
        throw new InvalidPayloadError(
            `${label} must be a non-empty even-length hexadecimal string`,
        );
    }

    assertValidX25519PublicKeyBytes(publicKeyBytes, label);
};

/**
 * Imports a transport private key from PKCS#8 hexadecimal bytes.
 *
 * @param privateKeyHex Lowercase hexadecimal PKCS#8 bytes.
 * @returns Imported transport private key.
 */
export const importTransportPrivateKey = async (
    privateKeyHex: EncodedTransportPrivateKey,
): Promise<CryptoKey> =>
    getWebCrypto().subtle.importKey(
        'pkcs8',
        toBufferSource(hexToBytes(privateKeyHex)),
        x25519Algorithm,
        true,
        ['deriveBits'],
    );

/**
 * Derives a raw shared secret for X25519.
 *
 * @param privateKey Local transport private key.
 * @param publicKey Peer transport public key.
 * @returns Raw shared secret bytes.
 */
export const deriveTransportSharedSecret = async (
    privateKey: CryptoKey,
    publicKey: CryptoKey,
): Promise<Uint8Array> => {
    const sharedSecret = new Uint8Array(
        await getWebCrypto().subtle.deriveBits(
            {
                name: 'X25519',
                public: publicKey,
            },
            privateKey,
            256,
        ),
    );

    assertNonZeroSharedSecret(sharedSecret);
    return sharedSecret;
};

/**
 * Re-derives the raw public key from a transport private key.
 *
 * @param privateKey Transport private key.
 * @returns Lowercase hexadecimal public key bytes.
 */
export const deriveTransportPublicKey = async (
    privateKey: CryptoKey,
): Promise<EncodedTransportPublicKey> => {
    const basePoint = await importTransportPublicKey(
        bytesToHex(X25519_BASE_POINT) as EncodedTransportPublicKey,
    );

    return bytesToHex(
        await deriveTransportSharedSecret(privateKey, basePoint),
    ) as EncodedTransportPublicKey;
};

/**
 * Verifies that a local transport private key matches the registered public key.
 *
 * @param privateKey Local transport private key.
 * @param expectedPublicKeyHex Registered public key bytes.
 * @returns `true` when the private key expands to `expectedPublicKeyHex`.
 */
export const verifyLocalTransportKey = async (
    privateKey: CryptoKey | EncodedTransportPrivateKey,
    expectedPublicKeyHex: EncodedTransportPublicKey,
): Promise<boolean> => {
    try {
        const resolvedPrivateKey =
            typeof privateKey === 'string'
                ? await importTransportPrivateKey(privateKey)
                : privateKey;

        return (
            (await deriveTransportPublicKey(resolvedPrivateKey)) ===
            expectedPublicKeyHex
        );
    } catch {
        return false;
    }
};
