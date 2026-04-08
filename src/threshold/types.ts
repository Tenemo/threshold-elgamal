import type { CryptoGroup } from '../core/types.js';
import type { ElgamalCiphertext } from '../elgamal/types.js';

/** A single indexed Shamir share over `Z_q`. */
export type Share = {
    /** 1-based participant index. */
    readonly index: number;
    /** Share value `f(index) mod q`. */
    readonly value: bigint;
};

/** Complete dealer-produced threshold key material. */
export type ThresholdKeySet = {
    /** Reconstruction threshold `k`. */
    readonly threshold: number;
    /** Total participant count `n`. */
    readonly participantCount: number;
    /** Group public key `Y = g^s mod p`. */
    readonly publicKey: bigint;
    /** Dealer-produced shares indexed `1..n`. */
    readonly shares: readonly Share[];
    /** Resolved built-in group definition. */
    readonly group: CryptoGroup;
};

/** A participant's partial decryption contribution. */
export type DecryptionShare = {
    /** 1-based participant index matching the source share. */
    readonly index: number;
    /** Partial decryption value `d_i = c1^{x_i} mod p`. */
    readonly value: bigint;
};

/** A threshold aggregate tied to a verified additive ciphertext. */
export type VerifiedAggregateCiphertext = {
    /** Canonical transcript hash that anchors the accepted ballot log. */
    readonly transcriptHash: string;
    /** Aggregate ciphertext recomputed from the accepted ballot log. */
    readonly ciphertext: ElgamalCiphertext;
};
