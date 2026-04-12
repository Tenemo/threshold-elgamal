import type { EncodedPoint } from '../core/types.js';
import type { ElGamalCiphertext } from '../elgamal/types.js';

/** A single indexed Shamir share over `Z_q`. */
export type Share = {
    /** 1-based participant index. */
    readonly index: number;
    /** Share value `f(index) mod q`. */
    readonly value: bigint;
};

/** A participant's partial decryption contribution. */
export type DecryptionShare = {
    /** 1-based participant index matching the source share. */
    readonly index: number;
    /** Partial decryption value `d_i = x_i C_1`. */
    readonly value: EncodedPoint;
};

const verifiedAggregateBrand: unique symbol = Symbol(
    'verifiedAggregateCiphertext',
);

/** A threshold aggregate tied to a verified additive ciphertext. */
export type VerifiedAggregateCiphertext = {
    /** Canonical transcript hash that anchors the accepted ballot log. */
    readonly transcriptHash: string;
    /** Aggregate ciphertext recomputed from the accepted ballot log. */
    readonly ciphertext: ElGamalCiphertext;
    /** Number of accepted ciphertexts that contributed to the aggregate. */
    readonly ballotCount: number;
    /** Opaque brand preventing arbitrary object-literal construction. */
    readonly [verifiedAggregateBrand]: true;
};

/**
 * Brands a locally recomputed aggregate ciphertext as verified without making
 * the brand property part of the public serialized shape.
 */
export const createVerifiedAggregateCiphertext = (
    transcriptHash: string,
    ciphertext: ElGamalCiphertext,
    ballotCount: number,
): VerifiedAggregateCiphertext =>
    Object.freeze(
        Object.defineProperty(
            {
                transcriptHash,
                ciphertext,
                ballotCount,
            },
            verifiedAggregateBrand,
            {
                value: true,
                enumerable: false,
            },
        ),
    ) as VerifiedAggregateCiphertext;
