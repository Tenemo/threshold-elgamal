import { describe, expect, it } from 'vitest';

import { InvalidScalarError, mod, modInvQ, modPowP, modQ } from '#core';

describe('core scalar helpers', () => {
    it('normalizes values into the field', () => {
        expect(modQ(-1n, 7n)).toBe(6n);
        expect(modQ(0n, 7n)).toBe(0n);
        expect(modQ(10n, 7n)).toBe(3n);
        expect(mod(-10n, 7n)).toBe(4n);
    });

    it('computes inverses and powers', () => {
        expect(modInvQ(3n, 11n)).toBe(4n);
        expect(modPowP(2n, 10n, 17n)).toBe(4n);
        expect(modInvQ(-3n, 11n)).toBe(7n);
        expect(modPowP(-15n, 7n, 97n)).toBe(14n);
    });

    it('rejects invalid moduli and exponents', () => {
        expect(() => mod(1n, 0n)).toThrow(InvalidScalarError);
        expect(() => modInvQ(1n, 0n)).toThrow(InvalidScalarError);
        expect(() => modInvQ(6n, 21n)).toThrow(InvalidScalarError);
        expect(() => modPowP(2n, -1n, 17n)).toThrow(InvalidScalarError);
    });
});
