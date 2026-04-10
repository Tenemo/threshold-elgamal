import { assertCanonicalRistrettoGroup } from '../core/group-invariants.js';
import { modQ, type CryptoGroup, type EncodedPoint } from '../core/index.js';
import {
    decodePoint,
    encodePoint,
    pointAdd,
    pointMultiply,
    RISTRETTO_ZERO,
} from '../core/ristretto.js';

export const evaluateCommitmentProduct = (
    commitments: readonly EncodedPoint[],
    index: number,
    group: CryptoGroup,
): EncodedPoint => {
    assertCanonicalRistrettoGroup(group, 'Commitment product group');

    let result = RISTRETTO_ZERO;
    let exponent = 1n;
    const point = BigInt(index);

    for (const commitment of commitments) {
        result = pointAdd(
            result,
            pointMultiply(decodePoint(commitment), exponent),
        );
        exponent = modQ(exponent * point, group.q);
    }

    return encodePoint(result);
};
