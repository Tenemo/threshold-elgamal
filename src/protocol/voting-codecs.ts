import type { DLEQProof, DisjunctiveProof } from '../proofs/types.js';
import { bigintToFixedHex, fixedHexToBigint } from '../serialize/index.js';

import { validateElectionManifest } from './manifest.js';
import type {
    ElectionManifest,
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
    ciphertext: { readonly c1: bigint; readonly c2: bigint },
    byteLength: number,
): EncodedCiphertext => ({
    c1: bigintToFixedHex(ciphertext.c1, byteLength),
    c2: bigintToFixedHex(ciphertext.c2, byteLength),
});

/**
 * Decodes a protocol ciphertext into bigint components.
 *
 * @param ciphertext Protocol ciphertext encoding.
 * @returns Decoded ciphertext.
 */
export const decodeCiphertext = (
    ciphertext: EncodedCiphertext,
): { readonly c1: bigint; readonly c2: bigint } => ({
    c1: fixedHexToBigint(ciphertext.c1),
    c2: fixedHexToBigint(ciphertext.c2),
});

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
): EncodedCompactProof => ({
    challenge: bigintToFixedHex(proof.challenge, byteLength),
    response: bigintToFixedHex(proof.response, byteLength),
});

/**
 * Decodes a protocol compact proof into bigint fields.
 *
 * @param proof Protocol proof encoding.
 * @returns Decoded compact proof.
 */
export const decodeCompactProof = (proof: EncodedCompactProof): DLEQProof => ({
    challenge: fixedHexToBigint(proof.challenge),
    response: fixedHexToBigint(proof.response),
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
 * Builds the ordered score domain implied by the manifest.
 *
 * @param manifest Validated election manifest.
 * @returns Ordered valid additive score values.
 */
export const manifestScoreDomain = (
    manifest: ElectionManifest,
): readonly bigint[] => {
    const validatedManifest = validateElectionManifest(manifest);

    return Array.from(
        {
            length:
                validatedManifest.scoreDomainMax -
                validatedManifest.scoreDomainMin +
                1,
        },
        (_value, index) => BigInt(validatedManifest.scoreDomainMin + index),
    );
};
