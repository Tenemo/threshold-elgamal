import { bytesToBigInt } from './bytes.js';
import { getWebCrypto } from './crypto.js';
import { InvalidScalarError } from './errors.js';
import type { RandomBytesSource } from './types.js';

const bitLength = (value: bigint): number =>
    value === 0n ? 0 : value.toString(2).length;
const MAX_WEB_CRYPTO_FILL_LENGTH = 65_536;

const secureRandomBytesSource: RandomBytesSource = (length) => {
    const bytes = new Uint8Array(length);
    let offset = 0;

    while (offset < length) {
        const chunkEnd = Math.min(offset + MAX_WEB_CRYPTO_FILL_LENGTH, length);
        getWebCrypto().getRandomValues(bytes.subarray(offset, chunkEnd));
        offset = chunkEnd;
    }

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
