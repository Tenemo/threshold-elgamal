import {
    assertInSubgroup,
    assertPlaintextAdditive,
    assertPlaintextMultiplicative,
    assertValidPublicKey,
    InvalidCiphertextError,
    InvalidScalarError,
    type CryptoGroup,
} from '../core/index.js';

import type { ElgamalCiphertext } from './types.js';

export const assertValidPrivateKey = (
    privateKey: bigint,
    group: CryptoGroup,
): void => {
    if (privateKey <= 0n || privateKey >= group.q) {
        throw new InvalidScalarError('Private key must be in the range 1..q-1');
    }
};

export const assertValidMultiplicativePublicKey = (
    publicKey: bigint,
    group: CryptoGroup,
): void => {
    assertValidPublicKey(publicKey, group.p, group.q);
};

export const assertValidAdditivePublicKey = (
    publicKey: bigint,
    group: CryptoGroup,
): void => {
    assertValidPublicKey(publicKey, group.p, group.q);
};

export const assertValidMultiplicativePlaintext = (
    value: bigint,
    group: CryptoGroup,
): void => {
    assertPlaintextMultiplicative(value, group.p);
};

export const assertValidAdditivePlaintext = (
    value: bigint,
    bound: bigint,
    group: CryptoGroup,
): void => {
    assertPlaintextAdditive(value, bound, group.q);
};

const assertNonZeroFieldElement = (
    value: bigint,
    group: CryptoGroup,
    label: string,
): void => {
    if (value <= 0n || value >= group.p) {
        throw new InvalidCiphertextError(
            `${label} must be in the range 1..p-1`,
        );
    }
};

export const assertValidMultiplicativeCiphertext = (
    ciphertext: ElgamalCiphertext,
    group: CryptoGroup,
): void => {
    assertInSubgroup(ciphertext.c1, group.p, group.q);
    assertNonZeroFieldElement(
        ciphertext.c2,
        group,
        'Multiplicative ciphertext c2',
    );
};

export const assertValidAdditiveCiphertext = (
    ciphertext: ElgamalCiphertext,
    group: CryptoGroup,
): void => {
    assertInSubgroup(ciphertext.c1, group.p, group.q);
    assertInSubgroup(ciphertext.c2, group.p, group.q);
};
