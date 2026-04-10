import type {
    CryptoGroup,
    EncodedPoint,
    GroupIdentifier,
} from '../core/types.js';

/** Accepted group identifier input for public ElGamal APIs. */
export type ElgamalGroupInput = GroupIdentifier;

/** Public and private key pair for the shipped Ristretto255 suite. */
export type ElgamalKeyPair = {
    /** Public key `Y = xG` encoded as a canonical Ristretto point. */
    readonly publicKey: EncodedPoint;
    /** Private scalar `x` in the range `1..q-1`. */
    readonly privateKey: bigint;
};

/** Key material plus the resolved immutable group definition. */
export type ElgamalParameters = ElgamalKeyPair & {
    /** Resolved built-in group parameters used to create the key pair. */
    readonly group: CryptoGroup;
};

/** Standard additive ElGamal ciphertext pair `(c1, c2)` encoded as points. */
export type ElgamalCiphertext = {
    /** Ephemeral component `rG`. */
    readonly c1: EncodedPoint;
    /** Payload component `mG + rY`. */
    readonly c2: EncodedPoint;
};
