import { assertMajorityThreshold } from './validation.js';

/**
 * Validates the shipped GJKR honest-majority threshold policy.
 *
 * @param threshold Reconstruction threshold `k`.
 * @param participantCount Total participant count `n`.
 * @returns The validated threshold.
 * @throws {@link ThresholdViolationError} When the threshold does not equal
 * the shipped `ceil(n / 2)` policy or the distributed ceremony is too small.
 */
export const assertDistributedThreshold = (
    threshold: number,
    participantCount: number,
): number => assertMajorityThreshold(threshold, participantCount);
