import { InvalidPayloadError } from '../core/index.js';
import { bigintToFixedHex } from '../serialize/index.js';

/** Primitive value accepted by the canonical JSON serializer. */
export type CanonicalJsonPrimitive = null | boolean | number | string | bigint;

/** Recursive JSON-like value accepted by the canonical JSON serializer. */
export type CanonicalJsonValue =
    | CanonicalJsonPrimitive
    | readonly CanonicalJsonValue[]
    | { readonly [key: string]: CanonicalJsonValue };

/** Options controlling canonical JSON serialization behavior. */
export type CanonicalJsonOptions = {
    readonly bigintByteLength?: number;
};

const canonicalize = (
    value: CanonicalJsonValue,
    options: CanonicalJsonOptions,
): string => {
    if (value === null || typeof value === 'boolean') {
        return JSON.stringify(value);
    }

    if (typeof value === 'number') {
        if (!Number.isFinite(value)) {
            throw new InvalidPayloadError(
                'Canonical JSON numbers must be finite',
            );
        }

        return JSON.stringify(value);
    }

    if (typeof value === 'string') {
        return JSON.stringify(value);
    }

    if (typeof value === 'bigint') {
        if (options.bigintByteLength === undefined) {
            throw new InvalidPayloadError(
                'Canonical JSON bigint values require an explicit byte length',
            );
        }

        return JSON.stringify(
            bigintToFixedHex(value, options.bigintByteLength),
        );
    }

    if (Array.isArray(value)) {
        const arrayValue = value as readonly CanonicalJsonValue[];
        return `[${arrayValue
            .map((item) => canonicalize(item, options))
            .join(',')}]`;
    }

    const objectValue = value as Readonly<Record<string, CanonicalJsonValue>>;
    const keys = Object.keys(objectValue).sort();
    return `{${keys
        .map((key) => {
            const entryValue: CanonicalJsonValue = objectValue[key];
            return `${JSON.stringify(key)}:${canonicalize(entryValue, options)}`;
        })
        .join(',')}}`;
};

/**
 * Canonically serializes JSON-compatible payloads with sorted keys and no
 * insignificant whitespace.
 *
 * BigInt values are encoded as fixed-width lowercase hexadecimal strings.
 *
 * @param value Canonical JSON value to serialize.
 * @param options Serialization options.
 * @returns Canonical JSON text.
 */
export const canonicalizeJson = (
    value: CanonicalJsonValue,
    options: CanonicalJsonOptions = {},
): string => canonicalize(value, options);
