import { InvalidScalarError } from './errors.js';
import type { RandomBytesSource } from './types.js';

const getCrypto = (): Crypto => {
    if (
        typeof globalThis.crypto === 'undefined' ||
        typeof globalThis.crypto.getRandomValues !== 'function'
    ) {
        throw new InvalidScalarError(
            'Web Crypto API is required for secure randomness',
        );
    }

    return globalThis.crypto;
};

const bitLength = (value: bigint): number =>
    value === 0n ? 0 : value.toString(2).length;

const bytesToBigInt = (bytes: Uint8Array): bigint => {
    if (bytes.length === 0) {
        return 0n;
    }

    let hex = '';
    for (const byte of bytes) {
        hex += byte.toString(16).padStart(2, '0');
    }

    return BigInt(`0x${hex}`);
};

const secureRandomBytesSource: RandomBytesSource = (length) => {
    const bytes = new Uint8Array(length);
    getCrypto().getRandomValues(bytes);
    return bytes;
};

export const randomBytes = (
    length: number,
    randomSource: RandomBytesSource = secureRandomBytesSource,
): Uint8Array => {
    if (!Number.isInteger(length) || length < 0) {
        throw new InvalidScalarError(
            'Random byte length must be a non-negative integer',
        );
    }

    const bytes = randomSource(length);
    if (bytes.length !== length) {
        throw new InvalidScalarError(
            'Random byte source returned an unexpected number of bytes',
        );
    }

    return bytes;
};

export const randomScalarBelow = (
    maxExclusive: bigint,
    randomSource: RandomBytesSource = secureRandomBytesSource,
): bigint => {
    if (maxExclusive <= 0n) {
        throw new InvalidScalarError('Upper bound must be positive');
    }

    const byteLength = Math.max(1, Math.ceil(bitLength(maxExclusive) / 8));

    for (;;) {
        const candidate = bytesToBigInt(randomBytes(byteLength, randomSource));
        if (candidate < maxExclusive) {
            return candidate;
        }
    }
};

export const randomScalarInRange = (
    minInclusive: bigint,
    maxExclusive: bigint,
    randomSource: RandomBytesSource = secureRandomBytesSource,
): bigint => {
    if (maxExclusive <= minInclusive) {
        throw new InvalidScalarError(
            'Range must satisfy minInclusive < maxExclusive',
        );
    }

    return (
        minInclusive +
        randomScalarBelow(maxExclusive - minInclusive, randomSource)
    );
};
