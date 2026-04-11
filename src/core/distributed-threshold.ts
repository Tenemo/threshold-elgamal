import { ThresholdViolationError } from './errors.js';
import { assertThreshold } from './validation.js';

/**
 * Validates the generic distributed threshold policy used by the shipped
 * manifest and GJKR workflows.
 *
 * @param threshold Reconstruction threshold `k`.
 * @param participantCount Total participant count `n`.
 * @returns The validated threshold.
 * @throws {@link ThresholdViolationError} When the generic `1 <= k <= n`
 * range is violated or the distributed ceremony is too small.
 */
export const assertDistributedThreshold = (
    threshold: number,
    participantCount: number,
): number => {
    assertThreshold(threshold, participantCount);

    if (participantCount < 3) {
        throw new ThresholdViolationError(
            'Distributed threshold workflows require at least three participants',
        );
    }

    return threshold;
};
