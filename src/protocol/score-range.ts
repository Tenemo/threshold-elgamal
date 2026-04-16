import { InvalidPayloadError } from '../core/index';

import type { ScoreRange } from './types';

const MAX_SUPPORTED_SCORE_RANGE_MAX = 100;

const assertSafeInteger = (value: number, label: string): void => {
    if (!Number.isSafeInteger(value)) {
        throw new InvalidPayloadError(`${label} must be a safe integer`);
    }
};

export const validateSupportedScoreRange = (
    scoreRange: ScoreRange,
    labels: {
        readonly comparisonMax?: string;
        readonly min: string;
        readonly max: string;
    },
): ScoreRange => {
    assertSafeInteger(scoreRange.min, labels.min);
    assertSafeInteger(scoreRange.max, labels.max);

    if (scoreRange.min < 0) {
        throw new InvalidPayloadError(`${labels.min} must be non-negative`);
    }
    if (scoreRange.max < 0) {
        throw new InvalidPayloadError(`${labels.max} must be non-negative`);
    }
    if (scoreRange.min > scoreRange.max) {
        throw new InvalidPayloadError(
            `${labels.min} must not exceed ${labels.comparisonMax ?? labels.max}`,
        );
    }
    if (scoreRange.max > MAX_SUPPORTED_SCORE_RANGE_MAX) {
        throw new InvalidPayloadError(
            `${labels.max} must not exceed ${MAX_SUPPORTED_SCORE_RANGE_MAX}`,
        );
    }

    return scoreRange;
};
