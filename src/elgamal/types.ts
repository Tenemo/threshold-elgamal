/**
 * Ciphertext types for additive ElGamal.
 *
 * These types are shared by low-level encryption helpers, ballot codecs,
 * threshold decryption, and the generated API reference.
 */
import type { EncodedPoint } from '../core/types';

/** Standard additive ElGamal ciphertext pair `(c1, c2)` encoded as points. */
export type ElGamalCiphertext = {
    /** Ephemeral component `rG`. */
    readonly c1: EncodedPoint;
    /** Payload component `mG + rY`. */
    readonly c2: EncodedPoint;
};
