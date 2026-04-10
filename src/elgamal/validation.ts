import {
    assertAdditiveBound,
    assertInSubgroup,
    assertInSubgroupOrIdentity,
    assertPlaintextAdditive,
    assertValidPublicKey,
    InvalidScalarError,
    type CryptoGroup,
} from '../core/index.js';

import type { ElgamalCiphertext } from './types.js';

/**
 * Validates that a private key lies in the range `1..q-1`.
 */
export const assertValidPrivateKey = (
    privateKey: bigint,
    group: CryptoGroup,
): void => {
    if (privateKey <= 0n || privateKey >= group.q) {
        throw new InvalidScalarError('Private key must be in the range 1..q-1');
    }
};

/** Validates an additive-mode public key against the selected group. */
export const assertValidAdditivePublicKey = (
    publicKey: string,
    group: CryptoGroup,
): void => {
    void group;
    assertValidPublicKey(publicKey);
};

/** Validates the caller-supplied additive plaintext bound. */
export const assertValidAdditiveBound = (
    bound: bigint,
    group: CryptoGroup,
): void => assertAdditiveBound(bound, group.q);

/** Validates the plaintext domain and caller-supplied bound for additive mode. */
export const assertValidAdditivePlaintext = (
    value: bigint,
    bound: bigint,
    group: CryptoGroup,
): void => assertPlaintextAdditive(value, bound, group.q);

/** Validates an additive ciphertext that may already be an aggregate. */
export const assertValidAdditiveCiphertext = (
    ciphertext: ElgamalCiphertext,
    group: CryptoGroup,
): void => {
    void group;
    assertInSubgroupOrIdentity(ciphertext.c1);
    assertInSubgroupOrIdentity(ciphertext.c2);
};

/** Validates a freshly produced additive ciphertext with non-identity `c1`. */
export const assertValidFreshAdditiveCiphertext = (
    ciphertext: ElgamalCiphertext,
    group: CryptoGroup,
): void => {
    void group;
    assertInSubgroup(ciphertext.c1);
    assertInSubgroupOrIdentity(ciphertext.c2);
};
