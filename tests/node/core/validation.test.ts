import { describe, expect, it } from 'vitest';

import {
    assertInSubgroup,
    assertPlaintextAdditive,
    assertPlaintextMultiplicative,
    assertScalarInZq,
    assertThreshold,
    assertValidParticipantIndex,
    assertValidPublicKey,
    getGroup,
    IndexOutOfRangeError,
    InvalidGroupElementError,
    InvalidScalarError,
    isInSubgroup,
    PlaintextDomainError,
    ThresholdViolationError,
} from '../../../src/core';

describe('core validation', () => {
    const group = getGroup(2048);

    it('accepts subgroup elements and rejects obvious invalid ones', () => {
        const validElement = 4n;

        expect(isInSubgroup(validElement, group.p, group.q)).toBe(true);
        expect(isInSubgroup(0n, group.p, group.q)).toBe(false);
        expect(isInSubgroup(1n, group.p, group.q)).toBe(false);
        expect(isInSubgroup(group.p - 1n, group.p, group.q)).toBe(false);
    });

    it('validates thresholds and indices', () => {
        expect(() => assertThreshold(2, 3)).not.toThrow();
        expect(() => assertValidParticipantIndex(1, 3)).not.toThrow();

        expect(() => assertThreshold(0, 3)).toThrow(ThresholdViolationError);
        expect(() => assertThreshold(4, 3)).toThrow(ThresholdViolationError);
        expect(() => assertValidParticipantIndex(0, 3)).toThrow(
            IndexOutOfRangeError,
        );
        expect(() => assertValidParticipantIndex(4, 3)).toThrow(
            IndexOutOfRangeError,
        );
    });

    it('validates scalar ranges and plaintext domains', () => {
        expect(() => assertScalarInZq(0n, group.q)).not.toThrow();
        expect(() => assertScalarInZq(group.q - 1n, group.q)).not.toThrow();
        expect(() => assertScalarInZq(group.q, group.q)).toThrow(
            InvalidScalarError,
        );

        expect(() => assertPlaintextMultiplicative(1n, group.p)).not.toThrow();
        expect(() => assertPlaintextMultiplicative(0n, group.p)).toThrow(
            PlaintextDomainError,
        );
        expect(() => assertPlaintextMultiplicative(group.p, group.p)).toThrow(
            PlaintextDomainError,
        );
        expect(() => assertPlaintextAdditive(0n, 10n, group.q)).not.toThrow();
        expect(() => assertPlaintextAdditive(10n, 10n, group.q)).not.toThrow();
        expect(() => assertPlaintextAdditive(-1n, 10n, group.q)).toThrow(
            PlaintextDomainError,
        );
        expect(() => assertPlaintextAdditive(11n, 10n, group.q)).toThrow(
            PlaintextDomainError,
        );
        expect(() => assertPlaintextAdditive(0n, group.q, group.q)).toThrow(
            InvalidScalarError,
        );
    });

    it('throws typed errors for invalid public subgroup elements', () => {
        expect(() => assertInSubgroup(1n, group.p, group.q)).toThrow(
            InvalidGroupElementError,
        );
        expect(() =>
            assertValidPublicKey(group.p - 1n, group.p, group.q),
        ).toThrow(InvalidGroupElementError);
        expect(() => assertValidPublicKey(4n, group.p, group.q)).not.toThrow();
    });
});
