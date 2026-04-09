import { InvalidScalarError } from './errors.js';

/** One base-exponent pair used by multi-exponentiation helpers. */
export type MultiExponentiationTerm = {
    readonly base: bigint;
    readonly exponent: bigint;
};

/** Optional pluggable bigint backend used for modular exponentiation. */
export type BigintMathBackend = {
    readonly modPow?: (
        base: bigint,
        exponent: bigint,
        modulus: bigint,
    ) => bigint;
};

const fixedBasePowerCache = new Map<string, bigint[]>();

let currentBackend: BigintMathBackend = Object.freeze({});

const assertPositiveModulus = (modulus: bigint): void => {
    if (modulus <= 0n) {
        throw new InvalidScalarError('Modulus must be positive');
    }
};

const normalize = (value: bigint, modulus: bigint): bigint => {
    const result = value % modulus;
    return result >= 0n ? result : result + modulus;
};

const extendedGcd = (
    a: bigint,
    b: bigint,
): { gcd: bigint; x: bigint; y: bigint } => {
    let oldR = a;
    let r = b;
    let oldS = 1n;
    let s = 0n;
    let oldT = 0n;
    let t = 1n;

    while (r !== 0n) {
        const quotient = oldR / r;
        [oldR, r] = [r, oldR - quotient * r];
        [oldS, s] = [s, oldS - quotient * s];
        [oldT, t] = [t, oldT - quotient * t];
    }

    return { gcd: oldR, x: oldS, y: oldT };
};

const modInv = (value: bigint, modulus: bigint): bigint => {
    const { gcd, x } = extendedGcd(value, modulus);
    if (gcd !== 1n) {
        throw new InvalidScalarError('Modular inverse does not exist');
    }

    return normalize(x, modulus);
};

const bitLength = (value: bigint): number =>
    value === 0n ? 1 : value.toString(2).length;

const jsModPow = (base: bigint, exponent: bigint, modulus: bigint): bigint => {
    if (modulus === 1n) {
        return 0n;
    }

    let result = 1n;
    let currentBase = normalize(base, modulus);
    let currentExponent = exponent;

    while (currentExponent > 0n) {
        if ((currentExponent & 1n) === 1n) {
            result = normalize(result * currentBase, modulus);
        }

        currentExponent >>= 1n;
        if (currentExponent > 0n) {
            currentBase = normalize(currentBase * currentBase, modulus);
        }
    }

    return result;
};

const fixedBaseCacheKey = (base: bigint, modulus: bigint): string =>
    `${modulus.toString(16)}:${base.toString(16)}`;

const ensureFixedBasePowers = (
    base: bigint,
    modulus: bigint,
    exponent: bigint,
): readonly bigint[] => {
    const key = fixedBaseCacheKey(base, modulus);
    const requiredLength = bitLength(exponent);
    const existing = fixedBasePowerCache.get(key) ?? [base];

    while (existing.length < requiredLength) {
        const previous = existing[existing.length - 1];
        existing.push(normalize(previous * previous, modulus));
    }

    fixedBasePowerCache.set(key, existing);

    return existing;
};

const modPowWithBackend = (
    base: bigint,
    exponent: bigint,
    modulus: bigint,
): bigint =>
    normalize(
        currentBackend.modPow?.(base, exponent, modulus) ??
            jsModPow(base, exponent, modulus),
        modulus,
    );

/**
 * Installs an optional bigint backend for modular exponentiation.
 *
 * Passing `null` or `undefined` restores the built-in JavaScript backend.
 *
 * @param backend Optional custom bigint backend.
 */
export const setBigintMathBackend = (
    backend?: BigintMathBackend | null,
): void => {
    currentBackend = Object.freeze({
        modPow: backend?.modPow,
    });
    fixedBasePowerCache.clear();
};

/** Returns the currently installed bigint backend. */
export const getBigintMathBackend = (): BigintMathBackend => currentBackend;

/** Restores the built-in JavaScript bigint backend. */
export const resetBigintMathBackend = (): void => {
    setBigintMathBackend();
};

/**
 * Computes `base^exponent mod modulus` using a fixed-base cache when the
 * built-in JavaScript backend is active.
 *
 * @throws {@link InvalidScalarError} When `modulus` is not positive or
 * `exponent` is negative.
 */
export const fixedBaseModPow = (
    base: bigint,
    exponent: bigint,
    modulus: bigint,
): bigint => {
    assertPositiveModulus(modulus);
    if (exponent < 0n) {
        throw new InvalidScalarError('Exponent must be non-negative');
    }
    if (currentBackend.modPow !== undefined) {
        return modPowWithBackend(normalize(base, modulus), exponent, modulus);
    }
    if (modulus === 1n) {
        return 0n;
    }
    if (exponent === 0n) {
        return 1n;
    }

    const normalizedBase = normalize(base, modulus);
    const powers = ensureFixedBasePowers(normalizedBase, modulus, exponent);
    let result = 1n;
    let currentExponent = exponent;
    let bitIndex = 0;

    while (currentExponent > 0n) {
        if ((currentExponent & 1n) === 1n) {
            result = normalize(result * powers[bitIndex], modulus);
        }

        currentExponent >>= 1n;
        bitIndex += 1;
    }

    return result;
};

/**
 * Computes `Π(base_i^exponent_i) mod modulus` with a shared JS bit walk.
 *
 * Custom backends fall back to repeated backend-backed exponentiations.
 *
 * @throws {@link InvalidScalarError} When `modulus` is not positive or any
 * exponent is negative.
 */
export const multiExponentiate = (
    terms: readonly MultiExponentiationTerm[],
    modulus: bigint,
): bigint => {
    assertPositiveModulus(modulus);

    const normalizedTerms = terms
        .filter((term) => term.exponent !== 0n)
        .map((term) => {
            if (term.exponent < 0n) {
                throw new InvalidScalarError('Exponent must be non-negative');
            }

            return {
                base: normalize(term.base, modulus),
                exponent: term.exponent,
            };
        });

    if (normalizedTerms.length === 0) {
        return 1n;
    }
    if (normalizedTerms.length === 1) {
        return fixedBaseModPow(
            normalizedTerms[0].base,
            normalizedTerms[0].exponent,
            modulus,
        );
    }
    if (currentBackend.modPow !== undefined) {
        return normalizedTerms.reduce(
            (product, term) =>
                normalize(
                    product *
                        modPowWithBackend(term.base, term.exponent, modulus),
                    modulus,
                ),
            1n,
        );
    }

    let result = 1n;
    const maxBits = Math.max(
        ...normalizedTerms.map((term) => bitLength(term.exponent)),
    );

    for (let bitIndex = maxBits - 1; bitIndex >= 0; bitIndex -= 1) {
        result = normalize(result * result, modulus);

        let factor = 1n;
        const bit = BigInt(bitIndex);
        for (const term of normalizedTerms) {
            if (((term.exponent >> bit) & 1n) === 1n) {
                factor = normalize(factor * term.base, modulus);
            }
        }

        result = normalize(result * factor, modulus);
    }

    return result;
};

/**
 * Reduces a value into the canonical range `0..modulus-1`.
 *
 * @throws {@link InvalidScalarError} When `modulus` is not positive.
 */
export const mod = (value: bigint, modulus: bigint): bigint => {
    assertPositiveModulus(modulus);
    return normalize(value, modulus);
};

/**
 * Reduces a value into the range `0..p-1`.
 *
 * @throws {@link InvalidScalarError} When `p` is not positive.
 */
export const modP = (value: bigint, p: bigint): bigint => mod(value, p);
/**
 * Reduces a value into the range `0..q-1`.
 *
 * @throws {@link InvalidScalarError} When `q` is not positive.
 */
export const modQ = (value: bigint, q: bigint): bigint => mod(value, q);

/**
 * Computes the multiplicative inverse of a value modulo `p`.
 *
 * @throws {@link InvalidScalarError} When `p` is not positive or the inverse
 * does not exist.
 */
export const modInvP = (value: bigint, p: bigint): bigint => {
    assertPositiveModulus(p);
    return modInv(modP(value, p), p);
};

/**
 * Computes the multiplicative inverse of a value modulo `q`.
 *
 * @throws {@link InvalidScalarError} When `q` is not positive or the inverse
 * does not exist.
 */
export const modInvQ = (value: bigint, q: bigint): bigint => {
    assertPositiveModulus(q);
    return modInv(modQ(value, q), q);
};

/**
 * Computes `base^exponent mod p` for non-negative exponents.
 *
 * @throws {@link InvalidScalarError} When `p` is not positive or `exponent` is
 * negative.
 */
export const modPowP = (base: bigint, exponent: bigint, p: bigint): bigint => {
    assertPositiveModulus(p);
    if (exponent < 0n) {
        throw new InvalidScalarError('Exponent must be non-negative');
    }
    return modPowWithBackend(modP(base, p), exponent, p);
};
