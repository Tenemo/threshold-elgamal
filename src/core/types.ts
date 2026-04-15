/**
 * Foundational nominal and suite types shared across the package.
 */
/**
 * Nominal typing helper used to distinguish compatible runtime values in the
 * type system.
 */
export type Brand<T, TBrand extends string> = T & {
    readonly __brand: TBrand;
};

/** @internal Canonical name for the built-in Ristretto255 suite. */
export type GroupName = 'ristretto255';
/** @internal Accepted helper input identifiers for the built-in Ristretto suite. */
export type GroupIdentifier = GroupName;

/**
 * Canonical 32-byte Ristretto point encoding exposed at the public boundary.
 *
 * Public helpers use this branded string type to distinguish encoded points
 * from ordinary hex strings.
 */
export type EncodedPoint = Brand<string, 'EncodedPoint'>;

/** @internal Immutable group definition for the built-in suite. */
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
 * Random byte source injected into sampling helpers for deterministic tests,
 * reproducible vectors, or custom runtime integration.
 */
export type RandomBytesSource = (length: number) => Uint8Array;
