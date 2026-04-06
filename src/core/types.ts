/**
 * Nominal typing helper used to distinguish compatible runtime values in the
 * type system.
 */
export type Brand<T, TBrand extends string> = T & {
    readonly __brand: TBrand;
};

/** Bit-size identifiers for the built-in RFC 7919 FFDHE suites. */
export type PrimeBits = 2048 | 3072 | 4096;
/** Canonical names for the built-in RFC 7919 FFDHE suites. */
export type GroupName = 'ffdhe2048' | 'ffdhe3072' | 'ffdhe4096';

/** Scalar value intended to live in the prime-order field `Z_q`. */
export type ScalarQ = Brand<bigint, 'ScalarQ'>;
/** Generic finite-field group element marker. */
export type GroupElement = Brand<bigint, 'GroupElement'>;
/** Element known to lie in the selected suite's prime-order subgroup. */
export type SubgroupElement = Brand<bigint, 'SubgroupElement'>;
/**
 * One-based roster index used by higher-level committee logic.
 *
 * Roster indices stay as small integers until threshold arithmetic converts
 * them to bigint values at the `Z_q` boundary.
 */
export type ParticipantIndex = Brand<number, 'ParticipantIndex'>;
/** Public key element that has already passed subgroup validation. */
export type ValidatedPublicKey = Brand<SubgroupElement, 'ValidatedPublicKey'>;

/** Immutable built-in group definition exposed by `getGroup()` and keygen APIs. */
export type CryptoGroup = {
    /** Canonical RFC 7919 suite name. */
    readonly name: GroupName;
    /** Prime modulus size in bits. */
    readonly bits: PrimeBits;
    /** Modulus size in bytes, used by fixed-width encodings. */
    readonly byteLength: number;
    /** Safe-prime modulus. */
    readonly p: bigint;
    /** Prime-order subgroup order. */
    readonly q: bigint;
    /** Primary subgroup generator used for ElGamal keys. */
    readonly g: bigint;
    /** Deterministically derived secondary subgroup generator. */
    readonly h: bigint;
    /** Rough classical security estimate in bits. */
    readonly securityEstimate: number;
};

/**
 * Random byte source injected into sampling helpers for deterministic testing
 * or custom runtime integration.
 */
export type RandomBytesSource = (length: number) => Uint8Array;
