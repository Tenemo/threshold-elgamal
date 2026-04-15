import type { EncodedPoint } from '../core/types';
import type { ElGamalCiphertext } from '../elgamal/types';

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

/** Public context needed to prepare a verified aggregate for decryption. */
export type AggregateDecryptionPreparationInput = {
    /** Verified aggregate recomputed from the accepted ballot transcript. */
    readonly aggregate: VerifiedAggregateCiphertext;
    /** Joint public key used to encrypt the original ballots. */
    readonly publicKey: EncodedPoint;
    /** Protocol namespace carried by the ceremony transcript. */
    readonly protocolVersion: string;
    /** Manifest hash that anchors the ceremony context. */
    readonly manifestHash: string;
    /** Session identifier that binds the ceremony instance. */
    readonly sessionId: string;
    /** 1-based manifest option index for the aggregate slot. */
    readonly optionIndex: number;
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
