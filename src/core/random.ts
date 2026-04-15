/**
 * Randomness helpers used by proof generation, envelope encryption, and other
 * cryptographic sampling paths.
 */
import { bytesToBigInt } from './bytes';
import { getWebCrypto } from './crypto';
import { InvalidScalarError } from './errors';
import type { RandomBytesSource } from './types';

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
 * @param length Number of random bytes to return.
 * @param randomSource Optional injected random source used for deterministic tests or custom runtimes.
 * @returns A `Uint8Array` with exactly `length` random bytes.
 *
 * @example
 * ```ts
 * const nonce = randomBytes(32);
 * ```
 *
 * @throws {@link InvalidScalarError} When `length` is negative, not an integer,
 * or the injected source returns the wrong number of bytes.
 * @throws {@link UnsupportedSuiteError} When the default Web Crypto source is
 * unavailable in the current runtime.
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
 * @param maxExclusive Exclusive upper bound for the sampled scalar.
 * @param randomSource Optional injected random source used for deterministic tests or custom runtimes.
 * @returns A uniformly sampled bigint below `maxExclusive`.
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

    if (maxExclusive === 1n) {
        return 0n;
    }

    const bits = bitLength(maxExclusive - 1n);
    const byteLength = Math.max(1, Math.ceil(bits / 8));
    const rem = bits % 8;
    const mask = rem === 0 ? 0xff : (1 << rem) - 1;

    for (;;) {
        const bytes = Uint8Array.from(randomBytes(byteLength, randomSource));
        bytes[0] &= mask;
        const candidate = bytesToBigInt(bytes);
        if (candidate < maxExclusive) {
            return candidate;
        }
    }
};

/**
 * Samples a uniform scalar from the range `minInclusive..maxExclusive-1`.
 *
 * @param minInclusive Inclusive lower bound for the sampled scalar.
 * @param maxExclusive Exclusive upper bound for the sampled scalar.
 * @param randomSource Optional injected random source used for deterministic tests or custom runtimes.
 * @returns A uniformly sampled bigint in the requested half-open range.
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
