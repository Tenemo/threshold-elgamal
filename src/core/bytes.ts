import { InvalidPayloadError } from './errors';

const hexPattern = /^[0-9a-f]+$/i;
const defaultHexErrorMessage =
    'Hex input must be a non-empty even-length hexadecimal string';

export const bytesToHex = (bytes: Uint8Array): string => {
    let hex = '';
    for (const byte of bytes) {
        hex += byte.toString(16).padStart(2, '0');
    }

    return hex;
};

export const hexToBytes = (
    hex: string,
    errorMessage: string = defaultHexErrorMessage,
): Uint8Array => {
    if (hex.length === 0 || hex.length % 2 !== 0 || !hexPattern.test(hex)) {
        throw new InvalidPayloadError(errorMessage);
    }

    const bytes = new Uint8Array(hex.length / 2);
    for (let index = 0; index < hex.length; index += 2) {
        bytes[index / 2] = Number.parseInt(hex.slice(index, index + 2), 16);
    }

    return bytes;
};

export const bytesToBigInt = (bytes: Uint8Array): bigint => {
    if (bytes.length === 0) {
        return 0n;
    }

    const hex = bytesToHex(bytes);
    return BigInt(`0x${hex}`);
};

export const bytesToBigIntLE = (bytes: Uint8Array): bigint => {
    let value = 0n;

    for (let index = bytes.length - 1; index >= 0; index -= 1) {
        value = (value << 8n) + BigInt(bytes[index]);
    }

    return value;
};

export const toBufferSource = (bytes: Uint8Array): ArrayBuffer =>
    Uint8Array.from(bytes).buffer;
