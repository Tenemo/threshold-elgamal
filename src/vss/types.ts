/** Feldman coefficient commitments `A_m = g^{a_m} mod p`. */
export type FeldmanCommitments = {
    /** Coefficient commitments in ascending polynomial order. */
    readonly commitments: readonly bigint[];
};

/** Pedersen coefficient commitments `C_m = g^{a_m} * h^{b_m} mod p`. */
export type PedersenCommitments = {
    /** Coefficient commitments in ascending polynomial order. */
    readonly commitments: readonly bigint[];
};

/** A Pedersen share pair for one participant index. */
export type PedersenShare = {
    /** 1-based participant index. */
    readonly index: number;
    /** Secret share `f(index) mod q`. */
    readonly secretValue: bigint;
    /** Blinding share `b(index) mod q`. */
    readonly blindingValue: bigint;
};
