import { assertScalarInZq, modQ } from '../core/index.js';
import { lagrangeCoefficient } from '../threshold/lagrange.js';
import type { Share } from '../threshold/types.js';

/**
 * Reconstructs the polynomial constant term from indexed Shamir shares.
 *
 * @param shares Indexed shares used for interpolation at `x = 0`.
 * @param q Prime-order subgroup order.
 * @returns Reconstructed constant term.
 */
export const reconstructSecretFromShares = (
    shares: readonly Share[],
    q: bigint,
): bigint => {
    const indices = shares.map((share) => BigInt(share.index));
    let secret = 0n;

    for (const share of shares) {
        assertScalarInZq(share.value, q);
        secret = modQ(
            secret +
                share.value *
                    lagrangeCoefficient(BigInt(share.index), indices, q),
            q,
        );
    }

    return secret;
};
