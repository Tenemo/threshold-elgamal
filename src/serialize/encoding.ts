import { InvalidPayloadError, InvalidScalarError } from '../core/errors';

const textEncoder = new TextEncoder();
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

export const bytesToHex = (bytes: Uint8Array): string => {
    let hex = '';
    for (const byte of bytes) {
        hex += byte.toString(16).padStart(2, '0');
    }
    return hex;
};

export const hexToBytes = (hex: string): Uint8Array => {
    if (hex.length === 0 || hex.length % 2 !== 0 || !hexPattern.test(hex)) {
        throw new InvalidPayloadError(
            'Hex input must be a non-empty even-length hexadecimal string',
        );
    }

    const bytes = new Uint8Array(hex.length / 2);
    for (let index = 0; index < hex.length; index += 2) {
        bytes[index / 2] = Number.parseInt(hex.slice(index, index + 2), 16);
    }
    return bytes;
};

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

export const fixedHexToBigint = (hex: string): bigint => {
    if (hex.length === 0 || hex.length % 2 !== 0 || !hexPattern.test(hex)) {
        throw new InvalidPayloadError(
            'Fixed-width hex input must be a non-empty even-length hexadecimal string',
        );
    }

    return BigInt(`0x${hex}`);
};

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

export const domainSeparator = (tag: string): Uint8Array =>
    textEncoder.encode(tag);

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
        return textEncoder.encode(element);
    }

    return new Uint8Array(element);
};

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
