import { modInv, modPow } from 'bigint-mod-arith';

import { InvalidScalarError } from './errors.js';

const assertPositiveModulus = (modulus: bigint): void => {
    if (modulus <= 0n) {
        throw new InvalidScalarError('Modulus must be positive');
    }
};

export const mod = (value: bigint, modulus: bigint): bigint => {
    assertPositiveModulus(modulus);
    return ((value % modulus) + modulus) % modulus;
};

export const modP = (value: bigint, p: bigint): bigint => mod(value, p);
export const modQ = (value: bigint, q: bigint): bigint => mod(value, q);

export const modInvP = (value: bigint, p: bigint): bigint => {
    assertPositiveModulus(p);
    return modInv(modP(value, p), p);
};

export const modInvQ = (value: bigint, q: bigint): bigint => {
    assertPositiveModulus(q);
    return modInv(modQ(value, q), q);
};

export const modPowP = (base: bigint, exponent: bigint, p: bigint): bigint => {
    assertPositiveModulus(p);
    if (exponent < 0n) {
        throw new InvalidScalarError('Exponent must be non-negative');
    }
    return modPow(modP(base, p), exponent, p);
};
