import { InvalidPayloadError, getWebCrypto } from '../core/index.js';
import { bytesToHex, hexToBytes } from '../serialize/index.js';

import type { KeyAgreementSuite, TransportKeyPair } from './types.js';

const toBufferSource = (bytes: Uint8Array): ArrayBuffer =>
    Uint8Array.from(bytes).buffer;

const X25519_BASE_POINT = (() => {
    const bytes = new Uint8Array(32);
    bytes[0] = 9;
    return bytes;
})();

const base64UrlToBytes = (value: string): Uint8Array => {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const padded = normalized.padEnd(
        normalized.length + ((4 - (normalized.length % 4)) % 4),
        '=',
    );

    if (typeof globalThis.atob !== 'function') {
        throw new InvalidPayloadError(
            'Base64url decoding requires global atob support',
        );
    }

    const decoded = globalThis.atob(padded);
    return Uint8Array.from(decoded, (character) => character.charCodeAt(0));
};

const buildP256RawPublicKey = (jwk: JsonWebKey): Uint8Array => {
    if (jwk.x === undefined || jwk.y === undefined) {
        throw new InvalidPayloadError(
            'P-256 private JWK export did not include x/y coordinates',
        );
    }

    return Uint8Array.from([
        0x04,
        ...base64UrlToBytes(jwk.x),
        ...base64UrlToBytes(jwk.y),
    ]);
};

const algorithmForSuite = (
    suite: KeyAgreementSuite,
): EcKeyImportParams | AlgorithmIdentifier =>
    suite === 'X25519'
        ? { name: 'X25519' }
        : { name: 'ECDH', namedCurve: 'P-256' };

const deriveAlgorithmForSuite = (
    publicKey: CryptoKey,
    suite: KeyAgreementSuite,
): EcdhKeyDeriveParams | AlgorithmIdentifier =>
    suite === 'X25519'
        ? { name: 'X25519', public: publicKey }
        : { name: 'ECDH', public: publicKey };

/** Options controlling transport-key generation. */
export type GenerateTransportKeyPairOptions = {
    /** Requested suite, or omitted to auto-select the preferred suite. */
    readonly suite?: KeyAgreementSuite;
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
 * Returns whether the current runtime supports X25519 via Web Crypto.
 *
 * @returns `true` when X25519 key generation is available.
 */
export const isX25519Supported = async (): Promise<boolean> => {
    try {
        const pair = await getWebCrypto().subtle.generateKey(
            { name: 'X25519' },
            true,
            ['deriveBits'],
        );

        await Promise.all([
            getWebCrypto().subtle.exportKey('raw', pair.publicKey),
            getWebCrypto().subtle.exportKey('pkcs8', pair.privateKey),
        ]);

        return true;
    } catch {
        return false;
    }
};

/**
 * Resolves the preferred key-agreement suite with X25519 fallback to P-256.
 *
 * @returns Supported key-agreement suite for the current runtime.
 */
export const resolveTransportSuite = async (): Promise<KeyAgreementSuite> =>
    (await isX25519Supported()) ? 'X25519' : 'P-256';

/**
 * Generates a transport key pair for the requested or preferred supported
 * suite.
 *
 * @param suite Requested suite, or omitted to auto-select the preferred suite.
 * @returns Transport key pair tagged with the resolved suite.
 */
export const generateTransportKeyPair = async (
    suiteOrOptions?: KeyAgreementSuite | GenerateTransportKeyPairOptions,
): Promise<TransportKeyPair> => {
    const options: GenerateTransportKeyPairOptions =
        typeof suiteOrOptions === 'string'
            ? {
                  suite: suiteOrOptions,
              }
            : (suiteOrOptions ?? {});
    const resolvedSuite = options.suite ?? (await resolveTransportSuite());
    const keyPair = (await getWebCrypto().subtle.generateKey(
        algorithmForSuite(resolvedSuite),
        options.extractable ?? false,
        ['deriveBits'],
    )) as CryptoKeyPair;

    return {
        suite: resolvedSuite,
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
): Promise<string> =>
    bytesToHex(
        new Uint8Array(await getWebCrypto().subtle.exportKey('raw', publicKey)),
    );

/**
 * Exports a transport private key as PKCS#8 lowercase hexadecimal bytes.
 *
 * @param privateKey Transport private key.
 * @returns Lowercase hexadecimal PKCS#8 bytes.
 */
export const exportTransportPrivateKey = async (
    privateKey: CryptoKey,
): Promise<string> =>
    bytesToHex(
        new Uint8Array(
            await getWebCrypto().subtle.exportKey('pkcs8', privateKey),
        ),
    );

/**
 * Imports a transport public key from raw hexadecimal bytes.
 *
 * @param publicKeyHex Lowercase hexadecimal public key bytes.
 * @param suite Transport key-agreement suite.
 * @returns Imported transport public key.
 */
export const importTransportPublicKey = async (
    publicKeyHex: string,
    suite: KeyAgreementSuite,
): Promise<CryptoKey> =>
    getWebCrypto().subtle.importKey(
        'raw',
        toBufferSource(hexToBytes(publicKeyHex)),
        algorithmForSuite(suite),
        true,
        [],
    );

/**
 * Imports a transport private key from PKCS#8 hexadecimal bytes.
 *
 * @param privateKeyHex Lowercase hexadecimal PKCS#8 bytes.
 * @param suite Transport key-agreement suite.
 * @returns Imported transport private key.
 */
export const importTransportPrivateKey = async (
    privateKeyHex: string,
    suite: KeyAgreementSuite,
): Promise<CryptoKey> =>
    getWebCrypto().subtle.importKey(
        'pkcs8',
        toBufferSource(hexToBytes(privateKeyHex)),
        algorithmForSuite(suite),
        true,
        ['deriveBits'],
    );

/**
 * Derives a raw shared secret for the selected transport suite.
 *
 * @param privateKey Local transport private key.
 * @param publicKey Peer transport public key.
 * @param suite Transport key-agreement suite.
 * @returns Raw shared secret bytes.
 */
export const deriveTransportSharedSecret = async (
    privateKey: CryptoKey,
    publicKey: CryptoKey,
    suite: KeyAgreementSuite,
): Promise<Uint8Array> => {
    const sharedSecret = new Uint8Array(
        await getWebCrypto().subtle.deriveBits(
            deriveAlgorithmForSuite(publicKey, suite),
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
 * @param suite Transport key-agreement suite.
 * @returns Lowercase hexadecimal public key bytes.
 */
export const deriveTransportPublicKey = async (
    privateKey: CryptoKey,
    suite: KeyAgreementSuite,
): Promise<string> => {
    if (suite === 'X25519') {
        const basePoint = await importTransportPublicKey(
            bytesToHex(X25519_BASE_POINT),
            suite,
        );

        return bytesToHex(
            await deriveTransportSharedSecret(privateKey, basePoint, suite),
        );
    }

    const jwk = await getWebCrypto().subtle.exportKey('jwk', privateKey);
    return bytesToHex(buildP256RawPublicKey(jwk));
};

/**
 * Verifies that a local transport private key matches the registered public key.
 *
 * @param privateKey Local transport private key.
 * @param expectedPublicKeyHex Registered public key bytes.
 * @param suite Transport key-agreement suite.
 * @returns `true` when the private key expands to `expectedPublicKeyHex`.
 */
export const verifyLocalTransportKey = async (
    privateKey: CryptoKey,
    expectedPublicKeyHex: string,
    suite: KeyAgreementSuite,
): Promise<boolean> =>
    (await deriveTransportPublicKey(privateKey, suite)) ===
    expectedPublicKeyHex;
