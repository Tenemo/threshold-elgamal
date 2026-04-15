/**
 * CDS94-style disjunctive proofs for additive score ballots.
 *
 * Ballot payloads use this module to prove that a ciphertext encodes one value
 * from the supported score domain without revealing which score was chosen.
 */
import {
    assertInSubgroup,
    assertInSubgroupOrIdentity,
    assertScalarInZq,
    InvalidProofError,
    modQ,
    randomScalarBelow,
    type CryptoGroup,
    type RandomBytesSource,
} from '../core/index';
import {
    decodePoint,
    encodePoint,
    multiplyBase,
    pointMultiply,
    pointSubtract,
} from '../core/ristretto';
import type { ElGamalCiphertext } from '../elgamal/types';
import {
    concatBytes,
    encodeForChallenge,
    encodeSequenceForChallenge,
} from '../serialize/encoding';

import {
    assertProofContext,
    contextElements,
    fixedPoint,
    fixedScalar,
    hashChallenge,
    sumChallenges,
} from './helpers';
import { hedgedNonce } from './nonces';
import type {
    DisjunctiveBranch,
    DisjunctiveProof,
    ProofContext,
} from './types';

const candidateEncoding = (
    ciphertext: ElGamalCiphertext,
    candidateValue: bigint,
    group: CryptoGroup,
): string =>
    encodePoint(
        pointSubtract(
            decodePoint(ciphertext.c2, 'Ciphertext c2'),
            multiplyBase(modQ(candidateValue, group.q)),
        ),
    );

const commitmentSequence = (
    commitments: readonly { a1: string; a2: string }[],
): Uint8Array =>
    encodeSequenceForChallenge(
        commitments.map((commitment) =>
            concatBytes(
                encodeForChallenge(fixedPoint(commitment.a1)),
                encodeForChallenge(fixedPoint(commitment.a2)),
            ),
        ),
    );

const challengePayload = (
    ciphertext: ElGamalCiphertext,
    publicKey: string,
    validValues: readonly bigint[],
    commitments: readonly { a1: string; a2: string }[],
    group: CryptoGroup,
    context: ProofContext,
): Uint8Array =>
    encodeForChallenge(
        ...contextElements(context),
        fixedPoint(group.g),
        fixedPoint(publicKey),
        fixedPoint(ciphertext.c1),
        fixedPoint(ciphertext.c2),
        encodeSequenceForChallenge(
            validValues.map((value) =>
                fixedScalar(modQ(value, group.q), group),
            ),
        ),
        commitmentSequence(commitments),
    );

/**
 * Creates a CDS94-style disjunctive proof for additive ElGamal plaintexts.
 *
 * In the supported voting flow this is the proof attached to every
 * `ballot-submission` payload.
 */
export const createDisjunctiveProof = async (
    plaintext: bigint,
    randomness: bigint,
    ciphertext: ElGamalCiphertext,
    publicKey: string,
    validValues: readonly bigint[],
    group: CryptoGroup,
    context: ProofContext,
    randomSource?: RandomBytesSource,
): Promise<DisjunctiveProof> => {
    assertProofContext(context, group);
    assertInSubgroup(publicKey);
    assertInSubgroup(ciphertext.c1);
    assertInSubgroupOrIdentity(ciphertext.c2);

    const realIndex = validValues.findIndex((value) => value === plaintext);
    if (realIndex < 0) {
        throw new InvalidProofError(
            'Disjunctive proof plaintext is not part of the allowed value set',
        );
    }

    const challenges: bigint[] = [];
    const responses: bigint[] = [];
    const commitments: { a1: string; a2: string }[] = [];

    for (const [index, candidateValue] of validValues.entries()) {
        const beta = candidateEncoding(ciphertext, candidateValue, group);

        if (index === realIndex) {
            challenges.push(0n);
            const nonce = await hedgedNonce(
                randomness,
                encodeForChallenge(
                    ...contextElements(context),
                    fixedPoint(publicKey),
                    fixedPoint(ciphertext.c1),
                    fixedPoint(ciphertext.c2),
                    fixedPoint(beta),
                ),
                group,
                randomSource,
            );
            responses.push(nonce);
            commitments.push({
                a1: encodePoint(multiplyBase(nonce)),
                a2: encodePoint(
                    pointMultiply(
                        decodePoint(publicKey, 'Ballot public key'),
                        nonce,
                    ),
                ),
            });
            continue;
        }

        const challenge = randomScalarBelow(group.q, randomSource);
        const response = randomScalarBelow(group.q, randomSource);

        challenges.push(challenge);
        responses.push(response);
        commitments.push({
            a1: encodePoint(
                pointSubtract(
                    multiplyBase(response),
                    pointMultiply(
                        decodePoint(ciphertext.c1, 'Ciphertext c1'),
                        challenge,
                    ),
                ),
            ),
            a2: encodePoint(
                pointSubtract(
                    pointMultiply(
                        decodePoint(publicKey, 'Ballot public key'),
                        response,
                    ),
                    pointMultiply(
                        decodePoint(beta, 'Candidate encoding'),
                        challenge,
                    ),
                ),
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
 * Ballot verification uses this to reject ciphertexts that do not encode one
 * of the allowed score values for the current option slot.
 */
export const verifyDisjunctiveProof = async (
    proof: DisjunctiveProof,
    ciphertext: ElGamalCiphertext,
    publicKey: string,
    validValues: readonly bigint[],
    group: CryptoGroup,
    context: ProofContext,
): Promise<boolean> => {
    assertProofContext(context, group);
    assertInSubgroup(publicKey);
    assertInSubgroup(ciphertext.c1);
    assertInSubgroupOrIdentity(ciphertext.c2);

    if (
        proof.branches.length !== validValues.length ||
        validValues.length === 0
    ) {
        return false;
    }

    for (const branch of proof.branches) {
        try {
            assertScalarInZq(branch.challenge, group.q);
            assertScalarInZq(branch.response, group.q);
        } catch {
            return false;
        }
    }

    const commitments = proof.branches.map((branch, index) => {
        const beta = candidateEncoding(ciphertext, validValues[index], group);

        return {
            a1: encodePoint(
                pointSubtract(
                    multiplyBase(branch.response),
                    pointMultiply(
                        decodePoint(ciphertext.c1, 'Ciphertext c1'),
                        branch.challenge,
                    ),
                ),
            ),
            a2: encodePoint(
                pointSubtract(
                    pointMultiply(
                        decodePoint(publicKey, 'Ballot public key'),
                        branch.response,
                    ),
                    pointMultiply(
                        decodePoint(beta, 'Candidate encoding'),
                        branch.challenge,
                    ),
                ),
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
