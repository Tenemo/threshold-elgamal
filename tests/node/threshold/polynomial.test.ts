import { describe, expect, it } from 'vitest';

import { InvalidScalarError, ThresholdViolationError, getGroup } from '#core';
import { evaluatePolynomial, generatePolynomial } from '#threshold';

describe('threshold polynomials', () => {
    it('generates exact-degree polynomials with the supplied constant term', () => {
        const group = getGroup(2048);
        const polynomial = generatePolynomial(12345n, 3, group.q);

        expect(polynomial).toHaveLength(3);
        expect(polynomial[0]).toBe(12345n);
        expect(polynomial[1]).toBeGreaterThanOrEqual(1n);
        expect(polynomial[2]).toBeGreaterThanOrEqual(1n);
    });

    it('rejects invalid thresholds and polynomial moduli', () => {
        const group = getGroup(2048);

        expect(() => generatePolynomial(1n, 0, group.q)).toThrow(
            ThresholdViolationError,
        );
        expect(() => generatePolynomial(1n, 1.5, group.q)).toThrow(
            ThresholdViolationError,
        );
        expect(() => generatePolynomial(1n, 1, 1n)).toThrow(InvalidScalarError);
    });

    it('evaluates polynomials over Z_q with Horner arithmetic', () => {
        const group = getGroup(2048);
        const polynomial = [5n, 3n, 7n] as const;

        expect(evaluatePolynomial(polynomial, 0n, group.q)).toBe(5n);
        expect(evaluatePolynomial(polynomial, 1n, group.q)).toBe(15n);
        expect(evaluatePolynomial(polynomial, 2n, group.q)).toBe(39n);
    });
});
