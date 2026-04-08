import { describe, expect, it } from 'vitest';

import {
    assertInSubgroup,
    assertInSubgroupOrIdentity,
    assertPlaintextAdditive,
    assertScalarInZq,
    assertThreshold,
    assertValidParticipantIndex,
    assertValidPublicKey,
    getGroup,
    IndexOutOfRangeError,
    InvalidGroupElementError,
    InvalidScalarError,
    isInSubgroup,
    isInSubgroupOrIdentity,
    PlaintextDomainError,
    ThresholdViolationError,
} from '#core';

describe('core validation', () => {
    const group = getGroup(2048);

    it('accepts subgroup elements and rejects obvious invalid ones', () => {
        const validElement = 4n;

        expect(isInSubgroup(validElement, group.p, group.q)).toBe(true);
        expect(isInSubgroupOrIdentity(validElement, group.p, group.q)).toBe(
            true,
        );
        expect(isInSubgroup(0n, group.p, group.q)).toBe(false);
        expect(isInSubgroup(1n, group.p, group.q)).toBe(false);
        expect(isInSubgroupOrIdentity(1n, group.p, group.q)).toBe(true);
        expect(isInSubgroup(group.p - 1n, group.p, group.q)).toBe(false);
    });

    it('validates scalar ranges and plaintext domains', () => {
        expect(() => assertScalarInZq(0n, group.q)).not.toThrow();
        expect(() => assertScalarInZq(group.q - 1n, group.q)).not.toThrow();
        expect(() => assertScalarInZq(group.q, group.q)).toThrow(
            InvalidScalarError,
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
            assertInSubgroupOrIdentity(1n, group.p, group.q),
        ).not.toThrow();
        expect(() =>
            assertValidPublicKey(group.p - 1n, group.p, group.q),
        ).toThrow(InvalidGroupElementError);
        expect(() => assertValidPublicKey(4n, group.p, group.q)).not.toThrow();
    });

    it('validates threshold and participant index domains', () => {
        expect(() => assertThreshold(3, 5)).not.toThrow();
        expect(() => assertThreshold(0, 5)).toThrow(ThresholdViolationError);
        expect(() => assertThreshold(6, 5)).toThrow(ThresholdViolationError);
        expect(() => assertThreshold(2.5, 5)).toThrow(ThresholdViolationError);

        expect(() => assertValidParticipantIndex(1, 5)).not.toThrow();
        expect(() => assertValidParticipantIndex(5, 5)).not.toThrow();
        expect(() => assertValidParticipantIndex(0, 5)).toThrow(
            IndexOutOfRangeError,
        );
        expect(() => assertValidParticipantIndex(6, 5)).toThrow(
            IndexOutOfRangeError,
        );
        expect(() => assertValidParticipantIndex(1.5, 5)).toThrow(
            IndexOutOfRangeError,
        );
    });
});
