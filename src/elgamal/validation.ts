import {
    RISTRETTO_GROUP,
    assertAdditiveBound,
    assertInSubgroup,
    assertInSubgroupOrIdentity,
    assertPlaintextAdditive,
    assertValidPublicKey,
    InvalidScalarError,
} from '../core/index.js';

import type { ElgamalCiphertext } from './types.js';

/**
 * Validates that a private key lies in the range `1..q-1`.
 */
export const assertValidPrivateKey = (privateKey: bigint): void => {
    if (privateKey <= 0n || privateKey >= RISTRETTO_GROUP.q) {
        throw new InvalidScalarError('Private key must be in the range 1..q-1');
    }
};

/** Validates an additive-mode public key against the shipped suite. */
export const assertValidAdditivePublicKey = (publicKey: string): void => {
    assertValidPublicKey(publicKey);
};

/** Validates the caller-supplied additive plaintext bound. */
export const assertValidAdditiveBound = (bound: bigint): void =>
    assertAdditiveBound(bound, RISTRETTO_GROUP.q);

/** Validates the plaintext domain and caller-supplied bound for additive mode. */
export const assertValidAdditivePlaintext = (
    value: bigint,
    bound: bigint,
): void => assertPlaintextAdditive(value, bound, RISTRETTO_GROUP.q);

/** Validates an additive ciphertext that may already be an aggregate. */
export const assertValidAdditiveCiphertext = (
    ciphertext: ElgamalCiphertext,
): void => {
    assertInSubgroupOrIdentity(ciphertext.c1);
    assertInSubgroupOrIdentity(ciphertext.c2);
};

/** Validates a freshly produced additive ciphertext with non-identity `c1`. */
export const assertValidFreshAdditiveCiphertext = (
    ciphertext: ElgamalCiphertext,
): void => {
    assertInSubgroup(ciphertext.c1);
    assertInSubgroupOrIdentity(ciphertext.c2);
};
