import { modInvQ, modQ } from '../core/index.js';

/**
 * Computes the Lagrange coefficient for `participantIndex` at `x = 0`.
 *
 * @param participantIndex Target share index as a bigint.
 * @param allIndices Full subset of indices participating in reconstruction.
 * @param q Prime-order subgroup order.
 * @returns `lambda_i mod q`.
 */
export const lagrangeCoefficient = (
    participantIndex: bigint,
    allIndices: readonly bigint[],
    q: bigint,
): bigint => {
    let numerator = 1n;
    let denominator = 1n;

    for (const otherIndex of allIndices) {
        if (otherIndex === participantIndex) {
            continue;
        }

        numerator = modQ(numerator * otherIndex, q);
        denominator = modQ(
            denominator * modQ(otherIndex - participantIndex, q),
            q,
        );
    }

    return modQ(numerator * modInvQ(denominator, q), q);
};
