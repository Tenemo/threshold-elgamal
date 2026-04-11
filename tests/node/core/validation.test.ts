import { describe, expect, it } from 'vitest';

import {
    assertMajorityThreshold,
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
    majorityThreshold,
    PlaintextDomainError,
    ThresholdViolationError,
} from '#core';
import { encodePoint, RISTRETTO_ZERO } from '#src/core/ristretto';

describe('core validation', () => {
    const group = getGroup('ristretto255');
    const identity = encodePoint(RISTRETTO_ZERO);
    const invalidPoint = 'ff'.repeat(32);

    it('accepts valid point encodings and rejects invalid or identity-only cases', () => {
        expect(isInSubgroup(group.g)).toBe(true);
        expect(isInSubgroupOrIdentity(group.g)).toBe(true);
        expect(isInSubgroup(identity)).toBe(false);
        expect(isInSubgroupOrIdentity(identity)).toBe(true);
        expect(isInSubgroup(invalidPoint)).toBe(false);
        expect(isInSubgroupOrIdentity(invalidPoint)).toBe(false);
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

    it('throws typed errors for invalid public points', () => {
        expect(() => assertInSubgroup(identity)).toThrow(
            InvalidGroupElementError,
        );
        expect(() => assertInSubgroupOrIdentity(identity)).not.toThrow();
        expect(isInSubgroup(group.g.toUpperCase())).toBe(false);
        expect(() => assertValidPublicKey(invalidPoint)).toThrow(
            InvalidGroupElementError,
        );
        expect(() => assertValidPublicKey(group.g.toUpperCase())).toThrow(
            InvalidGroupElementError,
        );
        expect(() => assertValidPublicKey(group.g)).not.toThrow();
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

    it('enforces the shipped ceil(n / 2) threshold for even groups', () => {
        expect(majorityThreshold(4)).toBe(2);

        expect(() => assertMajorityThreshold(1, 4)).toThrow(
            'Supported distributed threshold must equal ceil(n / 2) (expected 2 for n = 4)',
        );
        expect(() => assertMajorityThreshold(2, 4)).not.toThrow();
        expect(() => assertMajorityThreshold(3, 4)).toThrow(
            'Supported distributed threshold must equal ceil(n / 2) (expected 2 for n = 4)',
        );
    });

    it('rejects distributed thresholds when the ceremony is too small', () => {
        expect(() => assertMajorityThreshold(1, 2)).toThrow(
            'Distributed threshold workflows require at least three participants',
        );
        expect(() => assertMajorityThreshold(2, 2)).toThrow(
            'Distributed threshold workflows require at least three participants',
        );
    });

    it('accepts the shipped distributed threshold range and centralizes the ceremony-size guard', () => {
        expect(() => assertMajorityThreshold(2, 3)).not.toThrow();
        expect(() => assertMajorityThreshold(3, 5)).not.toThrow();
        expect(() => assertMajorityThreshold(0, 5)).toThrow(
            'Threshold 0 must satisfy 1 <= k <= n (n = 5)',
        );
        expect(() => assertMajorityThreshold(2, 2)).toThrow(
            'Distributed threshold workflows require at least three participants',
        );
    });

    it('derives the shipped majority threshold directly from the participant count', () => {
        expect(majorityThreshold(6)).toBe(3);
        expect(() => assertMajorityThreshold(3, 6)).not.toThrow();
        expect(() => assertMajorityThreshold(4, 6)).toThrow(
            'Supported distributed threshold must equal ceil(n / 2) (expected 3 for n = 6)',
        );
    });
});
