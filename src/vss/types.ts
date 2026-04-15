/**
 * Verifiable secret-sharing commitment and share types used by the GJKR DKG
 * implementation and transcript verifier.
 */
import type { EncodedPoint } from '../core/types';

/** Feldman coefficient commitments `A_m = a_m G`. */
export type FeldmanCommitments = {
    /** Coefficient commitments in ascending polynomial order. */
    readonly commitments: readonly EncodedPoint[];
};

/** Pedersen coefficient commitments `C_m = a_m G + b_m H`. */
export type PedersenCommitments = {
    /** Coefficient commitments in ascending polynomial order. */
    readonly commitments: readonly EncodedPoint[];
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
