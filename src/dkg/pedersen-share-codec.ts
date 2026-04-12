import { InvalidPayloadError, RISTRETTO_GROUP } from '../core/index';
import { canonicalizeJson } from '../protocol/canonical-json';
import { bigintToFixedHex, fixedHexToBigInt } from '../serialize/index';
import type { PedersenShare } from '../vss/types';

type PedersenShareEnvelopeRecord = {
    readonly blindingValue: string;
    readonly index: number;
    readonly secretValue: string;
};

const pedersenShareEnvelopeKeys = [
    'blindingValue',
    'index',
    'secretValue',
] as const;
const fixedLowercaseHexPattern = /^[0-9a-f]+$/;
const pedersenShareTextDecoder = new TextDecoder('utf-8', { fatal: true });

const assertCanonicalEnvelopeIndex = (
    value: unknown,
    expectedParticipantIndex: number,
    label: string,
): number => {
    if (typeof value !== 'number' || !Number.isInteger(value) || value < 1) {
        throw new InvalidPayloadError(
            `${label} share index must be a positive integer`,
        );
    }
    if (value !== expectedParticipantIndex) {
        throw new InvalidPayloadError(
            `${label} share index mismatch: expected ${expectedParticipantIndex}, received ${value}`,
        );
    }

    return value;
};

const parseCanonicalFixedHex = (
    value: unknown,
    byteLength: number,
    label: string,
): bigint => {
    const expectedLength = byteLength * 2;

    if (
        typeof value !== 'string' ||
        value.length !== expectedLength ||
        !fixedLowercaseHexPattern.test(value)
    ) {
        throw new InvalidPayloadError(
            `${label} must be a lowercase fixed-width hexadecimal string of length ${expectedLength}`,
        );
    }

    const decoded = fixedHexToBigInt(value);
    if (bigintToFixedHex(decoded, byteLength) !== value) {
        throw new InvalidPayloadError(
            `${label} must use canonical fixed-width hexadecimal encoding`,
        );
    }

    return decoded;
};

const parsePedersenShareEnvelopeRecord = (
    parsed: unknown,
    expectedParticipantIndex: number,
    label: string,
): PedersenShareEnvelopeRecord => {
    if (
        parsed === null ||
        Array.isArray(parsed) ||
        typeof parsed !== 'object'
    ) {
        throw new InvalidPayloadError(
            `${label} plaintext must be a JSON object`,
        );
    }

    const record = parsed as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    if (
        keys.length !== pedersenShareEnvelopeKeys.length ||
        !keys.every((key, index) => key === pedersenShareEnvelopeKeys[index])
    ) {
        throw new InvalidPayloadError(
            `${label} plaintext must contain only blindingValue, index, and secretValue`,
        );
    }

    return {
        blindingValue: bigintToFixedHex(
            parseCanonicalFixedHex(
                record.blindingValue,
                RISTRETTO_GROUP.scalarByteLength,
                `${label} blinding value`,
            ),
            RISTRETTO_GROUP.scalarByteLength,
        ),
        index: assertCanonicalEnvelopeIndex(
            record.index,
            expectedParticipantIndex,
            label,
        ),
        secretValue: bigintToFixedHex(
            parseCanonicalFixedHex(
                record.secretValue,
                RISTRETTO_GROUP.scalarByteLength,
                `${label} secret value`,
            ),
            RISTRETTO_GROUP.scalarByteLength,
        ),
    };
};

/** Encodes one Pedersen share pair for encrypted dealer-to-recipient transport. */
export const encodePedersenShareEnvelope = (
    share: PedersenShare,
    byteLength: number,
): string =>
    canonicalizeJson(
        {
            index: share.index,
            secretValue: bigintToFixedHex(share.secretValue, byteLength),
            blindingValue: bigintToFixedHex(share.blindingValue, byteLength),
        },
        {
            bigintByteLength: byteLength,
        },
    );

/** Decodes one encrypted Pedersen share pair after envelope decryption. */
export const decodePedersenShareEnvelope = (
    plaintext: Uint8Array,
    expectedParticipantIndex: number,
    label: string,
): PedersenShare => {
    let decodedPlaintext: string;

    try {
        decodedPlaintext = pedersenShareTextDecoder.decode(plaintext);
    } catch {
        throw new InvalidPayloadError(
            `${label} plaintext is not valid canonical JSON`,
        );
    }

    let parsed: PedersenShareEnvelopeRecord;

    try {
        parsed = parsePedersenShareEnvelopeRecord(
            JSON.parse(decodedPlaintext),
            expectedParticipantIndex,
            label,
        );
    } catch (error) {
        if (error instanceof InvalidPayloadError) {
            throw error;
        }

        throw new InvalidPayloadError(
            `${label} plaintext is not valid canonical JSON`,
        );
    }
    if (canonicalizeJson(parsed) !== decodedPlaintext) {
        throw new InvalidPayloadError(
            `${label} plaintext must use canonical JSON encoding`,
        );
    }

    return {
        index: parsed.index,
        secretValue: fixedHexToBigInt(parsed.secretValue),
        blindingValue: fixedHexToBigInt(parsed.blindingValue),
    };
};
