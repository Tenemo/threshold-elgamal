import { ristretto255, ristretto255_hasher } from '@noble/curves/ed25519.js';
import { sha512 } from '@noble/hashes/sha2.js';

import {
    bytesToBigInt,
    bytesToBigIntLE,
    bytesToHex,
    hexToBytes,
} from './bytes.js';
import { utf8ToBytes } from './crypto.js';
import {
    InvalidGroupElementError,
    InvalidPayloadError,
    InvalidScalarError,
} from './errors.js';
import type { EncodedPoint } from './types.js';

export type InternalPoint = InstanceType<typeof ristretto255.Point>;

export const RISTRETTO_GROUP_NAME = 'ristretto255';
const RISTRETTO_POINT = ristretto255.Point;
export const RISTRETTO_ORDER = ristretto255.Point.Fn.ORDER;
export const RISTRETTO_BYTE_LENGTH = 32;
export const RISTRETTO_SECURITY_ESTIMATE = 128;
export const RISTRETTO_BASE: InternalPoint = ristretto255.Point.BASE;
export const RISTRETTO_ZERO: InternalPoint = ristretto255.Point.ZERO;

const scalarByteLength = RISTRETTO_BYTE_LENGTH;
const pointHexLength = RISTRETTO_BYTE_LENGTH * 2;

const scalarToBytesLE = (value: bigint): Uint8Array => {
    if (value < 0n || value >= RISTRETTO_ORDER) {
        throw new InvalidScalarError(
            `Scalar ${value} is outside the valid Z_q range`,
        );
    }

    const bytes = new Uint8Array(scalarByteLength);
    let remaining = value;
    for (let index = 0; index < scalarByteLength; index += 1) {
        bytes[index] = Number(remaining & 0xffn);
        remaining >>= 8n;
    }

    return bytes;
};

const assertHexLength = (
    value: string,
    length: number,
    label: string,
): void => {
    if (value.length !== length || !/^[0-9a-f]+$/i.test(value)) {
        throw new InvalidPayloadError(
            `${label} must be a lowercase fixed-width hexadecimal string`,
        );
    }
};

export const encodePoint = (point: InternalPoint): EncodedPoint =>
    bytesToHex(point.toBytes()) as EncodedPoint;

export const decodePoint = (
    value: string,
    label = 'Point encoding',
): InternalPoint => {
    assertHexLength(value, pointHexLength, label);

    try {
        return RISTRETTO_POINT.fromHex(value);
    } catch {
        throw new InvalidGroupElementError(`${label} is not a valid point`);
    }
};

export const encodeScalar = (value: bigint): string =>
    bytesToHex(scalarToBytesLE(value));

export const decodeScalar = (
    value: string,
    label = 'Scalar encoding',
): bigint => {
    assertHexLength(value, pointHexLength, label);
    const scalar = bytesToBigIntLE(hexToBytes(value));

    if (scalar >= RISTRETTO_ORDER) {
        throw new InvalidScalarError(`${label} is outside the valid Z_q range`);
    }

    return scalar;
};

export const assertValidPoint = (value: string, label = 'Point'): void => {
    decodePoint(value, label);
};

export const assertNonIdentityPoint = (
    value: string,
    label = 'Point',
): void => {
    if (decodePoint(value, label).is0()) {
        throw new InvalidGroupElementError(`${label} must not be the identity`);
    }
};

export const pointAdd = (
    left: InternalPoint,
    right: InternalPoint,
): InternalPoint => left.add(right);

export const pointSubtract = (
    left: InternalPoint,
    right: InternalPoint,
): InternalPoint => left.subtract(right);

export const pointMultiply = (
    point: InternalPoint,
    scalar: bigint,
): InternalPoint => {
    if (scalar === 0n) {
        return RISTRETTO_ZERO;
    }

    return point.multiply(scalar);
};

export const multiplyBase = (scalar: bigint): InternalPoint => {
    if (scalar === 0n) {
        return RISTRETTO_ZERO;
    }

    return RISTRETTO_BASE.multiply(scalar);
};

export const derivePedersenGenerator = (): EncodedPoint => {
    const uniformBytes = sha512(
        utf8ToBytes('threshold-elgamal/ristretto255/pedersen-generator-h'),
    );
    return encodePoint(ristretto255_hasher.deriveToCurve!(uniformBytes));
};

export const hashChallengeToScalar = (payload: Uint8Array): bigint =>
    bytesToBigInt(sha512(payload)) % RISTRETTO_ORDER;
