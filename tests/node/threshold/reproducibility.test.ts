import { describe, expect, it } from 'vitest';

import { generateThresholdVectorRecord } from '../../../dev-support/threshold-reproducibility.js';

import { IndexOutOfRangeError } from '#core';

describe('threshold vector reproducibility', () => {
    const baseConfig = {
        bound: 10n,
        groupName: 'ristretto255',
        message: 3n,
        participantCount: 3,
        polynomial: [5n, 1n],
        randomness: 7n,
    } as const;

    it('rejects duplicate subset indices', () => {
        expect(() =>
            generateThresholdVectorRecord({
                ...baseConfig,
                subsetIndices: [1, 1],
            }),
        ).toThrow('Threshold vector subset indices must be unique');
    });

    it('rejects subset indices outside the participant range', () => {
        expect(() =>
            generateThresholdVectorRecord({
                ...baseConfig,
                subsetIndices: [1, 4],
            }),
        ).toThrow(IndexOutOfRangeError);
    });

    it('rejects non-integer subset indices', () => {
        expect(() =>
            generateThresholdVectorRecord({
                ...baseConfig,
                subsetIndices: [1.5, 2],
            }),
        ).toThrow(IndexOutOfRangeError);
    });
});
