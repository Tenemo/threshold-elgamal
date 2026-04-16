/**
 * Encode and decode helpers that bridge low-level cryptographic objects and
 * their published protocol payload representations.
 */
import { decodePoint, decodeScalar, encodeScalar } from '../core/ristretto';
import type { ElGamalCiphertext } from '../elgamal/types';
import type { DLEQProof, DisjunctiveProof } from '../proofs/types';

import { validateSupportedScoreRange } from './score-range';
import type {
    EncodedCiphertext,
    EncodedCompactProof,
    EncodedDisjunctiveProof,
    ScoreRange,
} from './types';

/**
 * Encodes an additive ciphertext into fixed-width protocol hex.
 *
 * @param ciphertext Ciphertext to encode.
 * @returns Protocol ciphertext encoding.
 */
export const encodeCiphertext = (
    ciphertext: ElGamalCiphertext,
): EncodedCiphertext => ({
    c1: ciphertext.c1,
    c2: ciphertext.c2,
});

/**
 * Decodes a protocol ciphertext into bigint components.
 *
 * @param ciphertext Protocol ciphertext encoding.
 * @returns Decoded ciphertext.
 */
export const decodeCiphertext = (
    ciphertext: EncodedCiphertext,
): ElGamalCiphertext => {
    decodePoint(ciphertext.c1, 'Ciphertext c1');
    decodePoint(ciphertext.c2, 'Ciphertext c2');

    return {
        c1: ciphertext.c1 as ElGamalCiphertext['c1'],
        c2: ciphertext.c2 as ElGamalCiphertext['c2'],
    };
};

/**
 * Encodes a compact challenge-response proof into fixed-width protocol hex.
 *
 * @param proof Compact proof to encode.
 * @returns Protocol proof encoding.
 */
export const encodeCompactProof = (proof: {
    readonly challenge: bigint;
    readonly response: bigint;
}): EncodedCompactProof => ({
    challenge: encodeScalar(proof.challenge),
    response: encodeScalar(proof.response),
});

/**
 * Decodes a protocol compact proof into bigint fields.
 *
 * @param proof Protocol proof encoding.
 * @returns Decoded compact proof.
 */
export const decodeCompactProof = (proof: EncodedCompactProof): DLEQProof => ({
    challenge: decodeScalar(proof.challenge, 'Compact proof challenge'),
    response: decodeScalar(proof.response, 'Compact proof response'),
});

/**
 * Encodes a disjunctive proof into fixed-width protocol hex.
 *
 * @param proof Disjunctive proof to encode.
 * @returns Protocol proof encoding.
 */
export const encodeDisjunctiveProof = (
    proof: DisjunctiveProof,
): EncodedDisjunctiveProof => ({
    branches: proof.branches.map((branch) => encodeCompactProof(branch)),
});

/**
 * Decodes a protocol disjunctive proof into bigint fields.
 *
 * @param proof Protocol proof encoding.
 * @returns Decoded disjunctive proof.
 */
export const decodeDisjunctiveProof = (
    proof: EncodedDisjunctiveProof,
): DisjunctiveProof => ({
    branches: proof.branches.map((branch) => decodeCompactProof(branch)),
});

/**
 * Expands one inclusive contiguous score range into its allowed plaintext
 * domain.
 *
 * Ballot builders and verifiers pass the resulting values into the
 * disjunctive-proof layer so each encrypted score can be proven to belong to
 * the manifest-declared domain.
 */
export const scoreRangeDomain = (scoreRange: ScoreRange): readonly bigint[] => {
    validateSupportedScoreRange(scoreRange, {
        min: 'Score range min',
        max: 'Score range max',
    });

    return Object.freeze(
        Array.from(
            { length: scoreRange.max - scoreRange.min + 1 },
            (_value, index) => BigInt(scoreRange.min + index),
        ),
    );
};
