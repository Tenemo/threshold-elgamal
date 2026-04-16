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
    IndexOutOfRangeError,
    InvalidGroupElementError,
    InvalidScalarError,
    isInSubgroup,
    isInSubgroupOrIdentity,
    majorityThreshold,
    PlaintextDomainError,
    RISTRETTO_GROUP,
    ThresholdViolationError,
} from '#core';
import { encodePoint, RISTRETTO_ZERO } from '#src/core/ristretto';

describe('core validation', () => {
    const group = RISTRETTO_GROUP;
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

    it.each([
        {
            participantCount: 3,
            threshold: 2,
            wrongThresholds: [1, 3],
        },
        {
            participantCount: 4,
            threshold: 2,
            wrongThresholds: [1, 3],
        },
        {
            participantCount: 5,
            threshold: 3,
            wrongThresholds: [2, 4],
        },
        {
            participantCount: 6,
            threshold: 3,
            wrongThresholds: [2, 4],
        },
    ])(
        'derives and enforces the shipped majority threshold for n = $participantCount',
        ({ participantCount, threshold, wrongThresholds }) => {
            expect(majorityThreshold(participantCount)).toBe(threshold);
            expect(() =>
                assertMajorityThreshold(threshold, participantCount),
            ).not.toThrow();

            for (const wrongThreshold of wrongThresholds) {
                expect(() =>
                    assertMajorityThreshold(wrongThreshold, participantCount),
                ).toThrow(
                    `Supported distributed threshold must equal ceil(n / 2) (expected ${threshold} for n = ${participantCount})`,
                );
            }
        },
    );

    it('preserves threshold-domain validation before the majority guard runs', () => {
        expect(() => assertMajorityThreshold(0, 5)).toThrow(
            'Threshold 0 must satisfy 1 <= k <= n (n = 5)',
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
});
