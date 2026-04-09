import { modP, modPowP, type CryptoGroup } from '../core/index.js';

export const evaluateCommitmentProduct = (
    commitments: readonly bigint[],
    index: number,
    group: CryptoGroup,
): bigint => {
    let result = 1n;
    let exponent = 1n;
    const point = BigInt(index);

    for (const commitment of commitments) {
        result = modP(result * modPowP(commitment, exponent, group.p), group.p);
        exponent = (exponent * point) % group.q;
    }

    return result;
};
