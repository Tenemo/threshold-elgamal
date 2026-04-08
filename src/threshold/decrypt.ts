import {
    assertInSubgroupOrIdentity,
    assertScalarInZq,
    IndexOutOfRangeError,
    InvalidShareError,
    modInvP,
    modP,
    modPowP,
    PlaintextDomainError,
    type CryptoGroup,
} from '../core/index.js';
import { babyStepGiantStep } from '../elgamal/bsgs.js';
import type { ElgamalCiphertext } from '../elgamal/types.js';

import { lagrangeCoefficient } from './lagrange.js';
import type {
    DecryptionShare,
    Share,
    VerifiedAggregateCiphertext,
} from './types.js';

const assertPositiveIndex = (index: number, label: string): void => {
    if (!Number.isInteger(index) || index < 1) {
        throw new IndexOutOfRangeError(
            `${label} index must be a positive integer`,
        );
    }
};

const assertUniqueIndices = (
    indices: readonly number[],
    label: string,
): void => {
    const seen = new Set<number>();

    for (const index of indices) {
        if (seen.has(index)) {
            throw new InvalidShareError(`${label} indices must be unique`);
        }
        seen.add(index);
    }
};

/**
 * Creates a partial decryption share `d_i = c1^{x_i} mod p`.
 *
 * Aggregate additive ciphertexts may legally have `c1 = 1`, so the first
 * component is validated against the subgroup-or-identity domain.
 *
 * @param ciphertext Ciphertext whose first component will be exponentiated.
 * @param share Indexed Shamir share.
 * @param group Resolved group definition.
 * @returns Partial decryption share tied to `share.index`.
 */
export const createDecryptionShare = (
    ciphertext: ElgamalCiphertext,
    share: Share,
    group: CryptoGroup,
): DecryptionShare => {
    assertPositiveIndex(share.index, 'Share');
    assertScalarInZq(share.value, group.q);
    assertInSubgroupOrIdentity(ciphertext.c1, group.p, group.q);

    return {
        index: share.index,
        value: modPowP(ciphertext.c1, share.value, group.p),
    };
};

/**
 * Combines indexed decryption shares via Lagrange interpolation at `x = 0`.
 *
 * @param ciphertext Ciphertext being decrypted.
 * @param decryptionShares Share subset used for reconstruction.
 * @param group Resolved group definition.
 * @param bound Maximum plaintext to search during additive discrete-log recovery.
 * @returns Recovered additive plaintext.
 *
 * @throws When the share set is empty or contains duplicate participant
 * indices.
 * @throws When the recovered plaintext exceeds the supplied bound.
 */
export const combineDecryptionShares = (
    ciphertext: ElgamalCiphertext,
    decryptionShares: readonly DecryptionShare[],
    group: CryptoGroup,
    bound: bigint,
): bigint => {
    if (decryptionShares.length === 0) {
        throw new InvalidShareError(
            'At least one decryption share is required for reconstruction',
        );
    }

    assertInSubgroupOrIdentity(ciphertext.c1, group.p, group.q);
    assertInSubgroupOrIdentity(ciphertext.c2, group.p, group.q);

    const indices = decryptionShares.map((share) => {
        assertPositiveIndex(share.index, 'Decryption share');
        assertInSubgroupOrIdentity(share.value, group.p, group.q);
        return share.index;
    });

    assertUniqueIndices(indices, 'Decryption share');

    const bigintIndices = indices.map((index) => BigInt(index));
    let combinedFactor = 1n;

    for (const share of decryptionShares) {
        const lambda = lagrangeCoefficient(
            BigInt(share.index),
            bigintIndices,
            group.q,
        );
        combinedFactor = modP(
            combinedFactor * modPowP(share.value, lambda, group.p),
            group.p,
        );
    }

    const encodedMessage = modP(
        ciphertext.c2 * modInvP(combinedFactor, group.p),
        group.p,
    );
    const message = babyStepGiantStep(encodedMessage, group.g, group.p, bound);

    if (message === null) {
        throw new PlaintextDomainError(
            'Threshold decryption result exceeds the supplied additive bound',
        );
    }

    return message;
};

/**
 * Creates a decryption share only for a locally recomputed aggregate that is
 * anchored to a canonical transcript hash.
 *
 * @param aggregate Verified aggregate ciphertext tied to a transcript hash.
 * @param share Indexed Shamir share.
 * @param group Resolved group definition.
 * @returns Partial decryption share for the verified aggregate.
 */
export const createVerifiedDecryptionShare = (
    aggregate: VerifiedAggregateCiphertext,
    share: Share,
    group: CryptoGroup,
): DecryptionShare => {
    if (aggregate.transcriptHash.trim() === '') {
        throw new InvalidShareError(
            'Verified aggregate ciphertext requires a non-empty transcript hash',
        );
    }

    return createDecryptionShare(aggregate.ciphertext, share, group);
};
