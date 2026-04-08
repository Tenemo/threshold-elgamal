import { bytesToHex as encodeBytesToHex } from '../core/bytes.js';
import { utf8ToBytes } from '../core/crypto.js';
import { InvalidPayloadError, InvalidScalarError } from '../core/errors.js';

const hexPattern = /^[0-9a-f]+$/i;

const encodeLength = (length: number): Uint8Array => {
    if (!Number.isInteger(length) || length < 0) {
        throw new InvalidPayloadError(
            'Encoded element length must be a non-negative integer',
        );
    }

    const bytes = new Uint8Array(4);
    const view = new DataView(bytes.buffer);
    view.setUint32(0, length, false);
    return bytes;
};

const assertHexInput = (hex: string, errorMessage: string): void => {
    if (hex.length === 0 || hex.length % 2 !== 0 || !hexPattern.test(hex)) {
        throw new InvalidPayloadError(errorMessage);
    }
};

/**
 * Encodes raw bytes as lowercase hexadecimal.
 *
 * @param bytes Raw bytes to encode.
 * @returns A lowercase hexadecimal string.
 */
export const bytesToHex = (bytes: Uint8Array): string =>
    encodeBytesToHex(bytes);

/**
 * Decodes a non-empty even-length hexadecimal string into bytes.
 *
 * @param hex Lowercase or uppercase hexadecimal input.
 * @returns Decoded bytes.
 *
 * @throws {@link InvalidPayloadError} When the input is not valid hexadecimal.
 */
export const hexToBytes = (hex: string): Uint8Array => {
    assertHexInput(
        hex,
        'Hex input must be a non-empty even-length hexadecimal string',
    );

    const bytes = new Uint8Array(hex.length / 2);
    for (let index = 0; index < hex.length; index += 2) {
        bytes[index / 2] = Number.parseInt(hex.slice(index, index + 2), 16);
    }
    return bytes;
};

/**
 * Encodes a non-negative bigint as fixed-width lowercase hexadecimal.
 *
 * @param value Non-negative bigint to encode.
 * @param byteLength Required output width in bytes.
 * @returns A lowercase hexadecimal string padded to exactly `byteLength * 2` characters.
 *
 * @throws {@link InvalidPayloadError} When `byteLength` is not positive.
 * @throws {@link InvalidScalarError} When the value is negative or does not fit
 * in the requested width.
 */
export const bigintToFixedHex = (value: bigint, byteLength: number): string => {
    if (!Number.isInteger(byteLength) || byteLength < 1) {
        throw new InvalidPayloadError(
            'Fixed-width hex encoding requires a positive byte length',
        );
    }

    if (value < 0n) {
        throw new InvalidScalarError(
            'Fixed-width hex encoding does not support negative bigint values',
        );
    }

    const hex = value.toString(16);
    const targetLength = byteLength * 2;

    if (hex.length > targetLength) {
        throw new InvalidScalarError(
            `Value ${value} does not fit in ${byteLength} bytes`,
        );
    }

    return hex.padStart(targetLength, '0');
};

/**
 * Encodes a non-negative bigint as fixed-width big-endian bytes.
 *
 * @param value Non-negative bigint to encode.
 * @param byteLength Required output width in bytes.
 * @returns A `Uint8Array` padded to exactly `byteLength`.
 *
 * @throws {@link InvalidPayloadError} When `byteLength` is not positive.
 * @throws {@link InvalidScalarError} When the value is negative or does not fit
 * in the requested width.
 */
export const bigintToFixedBytes = (
    value: bigint,
    byteLength: number,
): Uint8Array => hexToBytes(bigintToFixedHex(value, byteLength));

/**
 * Decodes a fixed-width hexadecimal string back into a bigint.
 *
 * @param hex Lowercase or uppercase hexadecimal input.
 * @returns The decoded bigint value.
 *
 * @throws {@link InvalidPayloadError} When the input is not valid hexadecimal.
 */
export const fixedHexToBigint = (hex: string): bigint => {
    assertHexInput(
        hex,
        'Fixed-width hex input must be a non-empty even-length hexadecimal string',
    );

    return BigInt(`0x${hex}`);
};

/**
 * Concatenates multiple byte arrays into a single contiguous buffer.
 *
 * @param arrays Byte arrays to concatenate in order.
 * @returns A single `Uint8Array` containing every input array.
 */
export const concatBytes = (...arrays: Uint8Array[]): Uint8Array => {
    const totalLength = arrays.reduce((sum, array) => sum + array.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;

    for (const array of arrays) {
        result.set(array, offset);
        offset += array.length;
    }

    return result;
};

/**
 * Encodes a domain-separation tag as UTF-8 bytes.
 *
 * @param tag Domain-separation string.
 * @returns UTF-8 bytes for `tag`.
 */
export const domainSeparator = (tag: string): Uint8Array => utf8ToBytes(tag);

const encodeBigIntForChallenge = (value: bigint): Uint8Array => {
    if (value < 0n) {
        throw new InvalidScalarError(
            'Challenge encoding does not support negative bigint values',
        );
    }

    const hex = value === 0n ? '00' : value.toString(16).padStart(2, '0');
    const evenHex = hex.length % 2 === 0 ? hex : `0${hex}`;
    return hexToBytes(evenHex);
};

const encodeChallengeElement = (
    element: bigint | Uint8Array | string,
): Uint8Array => {
    if (typeof element === 'bigint') {
        return encodeBigIntForChallenge(element);
    }

    if (typeof element === 'string') {
        return utf8ToBytes(element);
    }

    return new Uint8Array(element);
};

/**
 * Injectively encodes challenge transcript elements with 4-byte big-endian
 * length prefixes.
 *
 * This helper is intended for Fiat-Shamir style transcripts where different
 * element sequences must never collide after encoding.
 *
 * @param elements Transcript elements to encode in order.
 * @returns A deterministic length-prefixed byte encoding of `elements`.
 *
 * @example
 * ```ts
 * const payload = encodeForChallenge('dleq', 7n, new Uint8Array([1, 2, 3]));
 * ```
 *
 * @throws {@link InvalidScalarError} When a bigint element is negative.
 * @throws {@link InvalidPayloadError} When an encoded element length is invalid.
 */
export const encodeForChallenge = (
    ...elements: (bigint | Uint8Array | string)[]
): Uint8Array =>
    concatBytes(
        ...elements.map((element) => {
            const encodedElement = encodeChallengeElement(element);
            return concatBytes(
                encodeLength(encodedElement.length),
                encodedElement,
            );
        }),
    );

/**
 * Injectively encodes a variable-length sequence for challenge transcripts.
 *
 * The output starts with a 4-byte big-endian element count followed by the
 * standard length-prefixed encoding for each element.
 *
 * @param elements Sequence elements to encode in order.
 * @returns A deterministic count-prefixed byte encoding of `elements`.
 *
 * @throws {@link InvalidScalarError} When a bigint element is negative.
 * @throws {@link InvalidPayloadError} When an encoded element length is invalid.
 */
export const encodeSequenceForChallenge = (
    elements: readonly (bigint | Uint8Array | string)[],
): Uint8Array =>
    concatBytes(encodeLength(elements.length), encodeForChallenge(...elements));
