import { multiExponentiate, type CryptoGroup } from '../core/index.js';

export const evaluateCommitmentProduct = (
    commitments: readonly bigint[],
    index: number,
    group: CryptoGroup,
): bigint => {
    const terms: { base: bigint; exponent: bigint }[] = [];
    let exponent = 1n;
    const point = BigInt(index);

    for (const commitment of commitments) {
        terms.push({
            base: commitment,
            exponent,
        });
        exponent = (exponent * point) % group.q;
    }

    return multiExponentiate(terms, group.p);
};
