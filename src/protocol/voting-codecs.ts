import { decodePoint, decodeScalar, encodeScalar } from '../core/ristretto.js';
import type { ElgamalCiphertext } from '../elgamal/types.js';
import type { DLEQProof, DisjunctiveProof } from '../proofs/types.js';

import type {
    EncodedCiphertext,
    EncodedCompactProof,
    EncodedDisjunctiveProof,
} from './types.js';

/**
 * Encodes an additive ciphertext into fixed-width protocol hex.
 *
 * @param ciphertext Ciphertext to encode.
 * @param byteLength Fixed group byte width.
 * @returns Protocol ciphertext encoding.
 */
export const encodeCiphertext = (
    ciphertext: ElgamalCiphertext,
    byteLength: number,
): EncodedCiphertext => {
    void byteLength;

    return {
        c1: ciphertext.c1,
        c2: ciphertext.c2,
    };
};

/**
 * Decodes a protocol ciphertext into bigint components.
 *
 * @param ciphertext Protocol ciphertext encoding.
 * @returns Decoded ciphertext.
 */
export const decodeCiphertext = (
    ciphertext: EncodedCiphertext,
): ElgamalCiphertext => {
    decodePoint(ciphertext.c1, 'Ciphertext c1');
    decodePoint(ciphertext.c2, 'Ciphertext c2');

    return {
        c1: ciphertext.c1 as ElgamalCiphertext['c1'],
        c2: ciphertext.c2 as ElgamalCiphertext['c2'],
    };
};

/**
 * Encodes a compact challenge-response proof into fixed-width protocol hex.
 *
 * @param proof Compact proof to encode.
 * @param byteLength Fixed group byte width.
 * @returns Protocol proof encoding.
 */
export const encodeCompactProof = (
    proof: { readonly challenge: bigint; readonly response: bigint },
    byteLength: number,
): EncodedCompactProof => {
    void byteLength;

    return {
        challenge: encodeScalar(proof.challenge),
        response: encodeScalar(proof.response),
    };
};

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
 * @param byteLength Fixed group byte width.
 * @returns Protocol proof encoding.
 */
export const encodeDisjunctiveProof = (
    proof: DisjunctiveProof,
    byteLength: number,
): EncodedDisjunctiveProof => ({
    branches: proof.branches.map((branch) =>
        encodeCompactProof(branch, byteLength),
    ),
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
 * Returns the fixed shipped score-voting domain `1..10`.
 */
export const scoreVotingDomain = (): readonly bigint[] =>
    Object.freeze(
        Array.from({ length: 10 }, (_value, index) => BigInt(index + 1)),
    );
