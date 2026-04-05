import { InvalidScalarError, UnsupportedSuiteError } from './errors.js';

const textEncoder = new TextEncoder();

const toBufferSource = (bytes: Uint8Array): ArrayBuffer =>
    Uint8Array.from(bytes).buffer;

const assertByteLength = (length: number, label: string): void => {
    if (!Number.isInteger(length) || length < 0) {
        throw new InvalidScalarError(
            `${label} length must be a non-negative integer`,
        );
    }
};

export const utf8ToBytes = (value: string): Uint8Array =>
    textEncoder.encode(value);

export const getWebCrypto = (): Crypto => {
    if (
        typeof globalThis.crypto?.subtle === 'undefined' ||
        typeof globalThis.crypto.getRandomValues !== 'function'
    ) {
        throw new UnsupportedSuiteError(
            'Web Crypto API is required for v2 cryptographic operations',
        );
    }

    return globalThis.crypto;
};

export const sha256 = async (data: Uint8Array): Promise<Uint8Array> => {
    const crypto = getWebCrypto();
    const digest = await crypto.subtle.digest('SHA-256', toBufferSource(data));
    return new Uint8Array(digest);
};

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
