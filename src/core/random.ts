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

/**
 * Returns cryptographically secure random bytes.
 *
 * The default Web Crypto source is chunked into fills of at most 65,536 bytes
 * to avoid browser quota errors. Injected custom sources are called once with
 * the requested length.
 *
 * @example
 * ```ts
 * const nonce = randomBytes(32);
 * ```
 *
 * @throws {@link InvalidScalarError} When `length` is negative, not an integer,
 * or the injected source returns the wrong number of bytes.
 */
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

/**
 * Samples a uniform scalar from the range `0..maxExclusive-1` with rejection
 * sampling.
 *
 * @throws {@link InvalidScalarError} When `maxExclusive` is not positive.
 */
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

/**
 * Samples a uniform scalar from the range `minInclusive..maxExclusive-1`.
 *
 * @throws {@link InvalidScalarError} When the range is empty or inverted.
 */
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
