import { toBufferSource } from './bytes.js';
import { InvalidScalarError, UnsupportedSuiteError } from './errors.js';

const textEncoder = new TextEncoder();

const assertByteLength = (length: number, label: string): void => {
    if (!Number.isInteger(length) || length < 0) {
        throw new InvalidScalarError(
            `${label} length must be a non-negative integer`,
        );
    }
};

/** Encodes a JavaScript string as UTF-8 bytes. */
export const utf8ToBytes = (value: string): Uint8Array =>
    textEncoder.encode(value);

/**
 * Returns the runtime Web Crypto implementation used by the library.
 *
 * @throws {@link UnsupportedSuiteError} When the current runtime does not
 * expose `crypto.subtle` and `crypto.getRandomValues`.
 */
export const getWebCrypto = (): Crypto => {
    if (
        typeof globalThis.crypto?.subtle === 'undefined' ||
        typeof globalThis.crypto.getRandomValues !== 'function'
    ) {
        throw new UnsupportedSuiteError(
            'Web Crypto API is required for cryptographic operations',
        );
    }

    return globalThis.crypto;
};

/**
 * Hashes bytes with SHA-256.
 *
 * @throws {@link UnsupportedSuiteError} When Web Crypto is unavailable.
 */
export const sha256 = async (data: Uint8Array): Promise<Uint8Array> => {
    const crypto = getWebCrypto();
    const digest = await crypto.subtle.digest('SHA-256', toBufferSource(data));
    return new Uint8Array(digest);
};

/**
 * Derives deterministic key material with HKDF-SHA-256.
 *
 * @throws {@link InvalidScalarError} When `length` is negative or not an
 * integer.
 * @throws {@link UnsupportedSuiteError} When Web Crypto is unavailable.
 */
export const hkdfSha256 = async (
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length: number,
): Promise<Uint8Array> => {
    assertByteLength(length, 'HKDF output');

    const crypto = getWebCrypto();
    const baseKey = await crypto.subtle.importKey(
        'raw',
        toBufferSource(ikm),
        'HKDF',
        false,
        ['deriveBits'],
    );
    const derivedBits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: toBufferSource(salt),
            info: toBufferSource(info),
        },
        baseKey,
        length * 8,
    );

    return new Uint8Array(derivedBits);
};
