import {
    assertInSubgroup,
    assertInSubgroupOrIdentity,
    InvalidProofError,
    modInvP,
    modP,
    modPowP,
    modQ,
    randomScalarBelow,
    type CryptoGroup,
    type RandomBytesSource,
} from '../core/index.js';
import type { ElgamalCiphertext } from '../elgamal/types.js';
import {
    bigintToFixedBytes,
    concatBytes,
    encodeForChallenge,
    encodeSequenceForChallenge,
} from '../serialize/index.js';

import {
    assertProofContext,
    contextElements,
    fixed,
    hashChallenge,
    negateExponent,
    sumChallenges,
} from './helpers.js';
import { hedgedNonce } from './nonces.js';
import type {
    DisjunctiveBranch,
    DisjunctiveProof,
    ProofContext,
} from './types.js';

const candidateEncoding = (
    ciphertext: ElgamalCiphertext,
    candidateValue: bigint,
    group: CryptoGroup,
): bigint =>
    modP(
        ciphertext.c2 *
            modInvP(modPowP(group.g, candidateValue, group.p), group.p),
        group.p,
    );

const commitmentSequence = (
    commitments: readonly { a1: bigint; a2: bigint }[],
    group: CryptoGroup,
): Uint8Array =>
    encodeSequenceForChallenge(
        commitments.map((commitment) =>
            concatBytes(
                encodeForChallenge(fixed(commitment.a1, group)),
                encodeForChallenge(fixed(commitment.a2, group)),
            ),
        ),
    );

const challengePayload = (
    ciphertext: ElgamalCiphertext,
    publicKey: bigint,
    validValues: readonly bigint[],
    commitments: readonly { a1: bigint; a2: bigint }[],
    group: CryptoGroup,
    context: ProofContext,
): Uint8Array =>
    encodeForChallenge(
        ...contextElements(context),
        fixed(group.g, group),
        fixed(publicKey, group),
        fixed(ciphertext.c1, group),
        fixed(ciphertext.c2, group),
        encodeSequenceForChallenge(
            validValues.map((value) =>
                bigintToFixedBytes(value, group.byteLength),
            ),
        ),
        commitmentSequence(commitments, group),
    );

/**
 * Creates a CDS94-style disjunctive proof for additive ElGamal plaintexts.
 *
 * @param plaintext Actual plaintext encoded in the ciphertext.
 * @param randomness Encryption randomness used for the ciphertext.
 * @param ciphertext Fresh additive ciphertext.
 * @param publicKey Additive-mode public key.
 * @param validValues Ordered set of valid plaintext values.
 * @param group Resolved group definition.
 * @param context Fiat-Shamir binding context.
 * @param randomSource Optional random source used for deterministic tests.
 * @returns Compact disjunctive proof with one branch per valid value.
 */
export const createDisjunctiveProof = async (
    plaintext: bigint,
    randomness: bigint,
    ciphertext: ElgamalCiphertext,
    publicKey: bigint,
    validValues: readonly bigint[],
    group: CryptoGroup,
    context: ProofContext,
    randomSource?: RandomBytesSource,
): Promise<DisjunctiveProof> => {
    assertProofContext(context, group);
    assertInSubgroup(publicKey, group.p, group.q);
    assertInSubgroup(ciphertext.c1, group.p, group.q);
    assertInSubgroupOrIdentity(ciphertext.c2, group.p, group.q);

    const realIndex = validValues.findIndex((value) => value === plaintext);
    if (realIndex < 0) {
        throw new InvalidProofError(
            'Disjunctive proof plaintext is not part of the allowed value set',
        );
    }

    const challenges: bigint[] = [];
    const responses: bigint[] = [];
    const commitments: { a1: bigint; a2: bigint }[] = [];

    for (const [index, candidateValue] of validValues.entries()) {
        const beta = candidateEncoding(ciphertext, candidateValue, group);

        if (index === realIndex) {
            challenges.push(0n);
            const nonce = await hedgedNonce(
                randomness,
                encodeForChallenge(
                    ...contextElements(context),
                    fixed(publicKey, group),
                    fixed(ciphertext.c1, group),
                    fixed(ciphertext.c2, group),
                    fixed(beta, group),
                ),
                group,
                randomSource,
            );
            responses.push(nonce);
            commitments.push({
                a1: modPowP(group.g, nonce, group.p),
                a2: modPowP(publicKey, nonce, group.p),
            });
            continue;
        }

        const challenge = randomScalarBelow(group.q, randomSource);
        const response = randomScalarBelow(group.q, randomSource);

        challenges.push(challenge);
        responses.push(response);
        commitments.push({
            a1: modP(
                modPowP(group.g, response, group.p) *
                    modPowP(
                        ciphertext.c1,
                        negateExponent(challenge, group.q),
                        group.p,
                    ),
                group.p,
            ),
            a2: modP(
                modPowP(publicKey, response, group.p) *
                    modPowP(beta, negateExponent(challenge, group.q), group.p),
                group.p,
            ),
        });
    }

    const challenge = await hashChallenge(
        challengePayload(
            ciphertext,
            publicKey,
            validValues,
            commitments,
            group,
            context,
        ),
        group.q,
    );
    const simulatedSum = sumChallenges(
        challenges.filter((_value, index) => index !== realIndex),
        group.q,
    );
    const realChallenge = modQ(challenge - simulatedSum, group.q);

    challenges[realIndex] = realChallenge;
    responses[realIndex] = modQ(
        responses[realIndex] + realChallenge * randomness,
        group.q,
    );

    return {
        branches: challenges.map(
            (branchChallenge, index): DisjunctiveBranch => ({
                challenge: branchChallenge,
                response: responses[index],
            }),
        ),
    };
};

/**
 * Verifies a CDS94-style disjunctive proof for additive ElGamal plaintexts.
 *
 * @param proof Compact disjunctive proof with one branch per valid value.
 * @param ciphertext Fresh additive ciphertext.
 * @param publicKey Additive-mode public key.
 * @param validValues Ordered set of valid plaintext values.
 * @param group Resolved group definition.
 * @param context Fiat-Shamir binding context.
 * @returns `true` when the proof verifies.
 */
export const verifyDisjunctiveProof = async (
    proof: DisjunctiveProof,
    ciphertext: ElgamalCiphertext,
    publicKey: bigint,
    validValues: readonly bigint[],
    group: CryptoGroup,
    context: ProofContext,
): Promise<boolean> => {
    assertProofContext(context, group);
    assertInSubgroup(publicKey, group.p, group.q);
    assertInSubgroup(ciphertext.c1, group.p, group.q);
    assertInSubgroupOrIdentity(ciphertext.c2, group.p, group.q);

    if (
        proof.branches.length !== validValues.length ||
        validValues.length === 0
    ) {
        return false;
    }

    const commitments = proof.branches.map((branch, index) => {
        const beta = candidateEncoding(ciphertext, validValues[index], group);

        return {
            a1: modP(
                modPowP(group.g, branch.response, group.p) *
                    modPowP(
                        ciphertext.c1,
                        negateExponent(branch.challenge, group.q),
                        group.p,
                    ),
                group.p,
            ),
            a2: modP(
                modPowP(publicKey, branch.response, group.p) *
                    modPowP(
                        beta,
                        negateExponent(branch.challenge, group.q),
                        group.p,
                    ),
                group.p,
            ),
        };
    });
    const expected = await hashChallenge(
        challengePayload(
            ciphertext,
            publicKey,
            validValues,
            commitments,
            group,
            context,
        ),
        group.q,
    );

    return (
        expected ===
        sumChallenges(
            proof.branches.map((branch) => branch.challenge),
            group.q,
        )
    );
};
