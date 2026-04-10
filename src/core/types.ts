/**
 * Nominal typing helper used to distinguish compatible runtime values in the
 * type system.
 */
export type Brand<T, TBrand extends string> = T & {
    readonly __brand: TBrand;
};

/** Canonical name for the shipped Ristretto255 suite. */
export type GroupName = 'ristretto255';
/** Legacy finite-field suite labels accepted as beta input aliases only. */
export type LegacyGroupName = 'ffdhe2048' | 'ffdhe3072' | 'ffdhe4096';
/** Legacy finite-field bit-size labels accepted as beta input aliases only. */
export type PrimeBits = 2048 | 3072 | 4096;
/** Accepted helper input identifiers for the shipped Ristretto suite. */
export type GroupIdentifier = GroupName | LegacyGroupName | PrimeBits;

/** Canonical 32-byte Ristretto point encoding exposed at the public boundary. */
export type EncodedPoint = Brand<string, 'EncodedPoint'>;

/** Scalar value intended to live in the prime-order field `Z_q`. */
export type ScalarQ = Brand<bigint, 'ScalarQ'>;

/** Immutable built-in group definition exposed by `getGroup()` and keygen APIs. */
export type CryptoGroup = {
    /** Canonical suite name. */
    readonly name: GroupName;
    /** Canonical point encoding width in bytes. */
    readonly byteLength: number;
    /** Canonical scalar encoding width in bytes. */
    readonly scalarByteLength: number;
    /** Prime-order subgroup order. */
    readonly q: bigint;
    /** Primary generator encoded as a canonical Ristretto point. */
    readonly g: EncodedPoint;
    /** Deterministically derived secondary generator encoded as a canonical Ristretto point. */
    readonly h: EncodedPoint;
    /** Rough classical security estimate in bits. */
    readonly securityEstimate: number;
};

/**
 * Random byte source injected into sampling helpers for deterministic testing
 * or custom runtime integration.
 */
export type RandomBytesSource = (length: number) => Uint8Array;
