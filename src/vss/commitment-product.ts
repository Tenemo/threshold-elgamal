import { modQ, type CryptoGroup } from '../core/index.js';
import {
    decodePoint,
    encodePoint,
    pointAdd,
    pointMultiply,
    RISTRETTO_ZERO,
} from '../core/ristretto.js';

export const evaluateCommitmentProduct = (
    commitments: readonly string[],
    index: number,
    group: CryptoGroup,
): string => {
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
