import type { CryptoGroup, GroupName, PrimeBits } from '../core/types.js';

/** Accepted group identifier input for public ElGamal APIs. */
export type ElgamalGroupInput = GroupName | PrimeBits;

/** Public and private key pair for a selected ElGamal suite. */
export type ElgamalKeyPair = {
    /** Public key `y = g^x mod p`. */
    readonly publicKey: bigint;
    /** Private scalar `x` in the range `1..q-1`. */
    readonly privateKey: bigint;
};

/** Key material plus the resolved immutable group definition. */
export type ElgamalParameters = ElgamalKeyPair & {
    /** Resolved built-in group parameters used to create the key pair. */
    readonly group: CryptoGroup;
};

/** Standard ElGamal ciphertext pair `(c1, c2)`. */
export type ElgamalCiphertext = {
    /** Ephemeral component `g^r mod p`. */
    readonly c1: bigint;
    /** Payload component whose interpretation depends on the selected mode. */
    readonly c2: bigint;
};
