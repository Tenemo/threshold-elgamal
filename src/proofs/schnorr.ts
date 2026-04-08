import {
    assertInSubgroup,
    assertScalarInZq,
    modP,
    modPowP,
    modQ,
    type CryptoGroup,
    type RandomBytesSource,
} from '../core/index.js';
import { encodeForChallenge } from '../serialize/index.js';

import {
    assertProofContext,
    contextElements,
    fixed,
    hashChallenge,
    negateExponent,
} from './helpers.js';
import { hedgedNonce } from './nonces.js';
import type { ProofContext, SchnorrProof } from './types.js';

const nonceContext = (
    statement: bigint,
    group: CryptoGroup,
    context: ProofContext,
): Uint8Array =>
    encodeForChallenge(
        ...contextElements(context),
        fixed(group.g, group),
        fixed(group.q, group),
        fixed(statement, group),
    );

const challengePayload = (
    statement: bigint,
    commitment: bigint,
    group: CryptoGroup,
    context: ProofContext,
): Uint8Array =>
    encodeForChallenge(
        ...contextElements(context),
        fixed(group.g, group),
        fixed(group.q, group),
        fixed(statement, group),
        fixed(commitment, group),
    );

/**
 * Creates a compact additive-form Schnorr proof of knowledge.
 *
 * @param secret Witness scalar.
 * @param statement Statement element `g^secret mod p`.
 * @param group Resolved group definition.
 * @param context Fiat-Shamir binding context.
 * @param randomSource Optional random source used for deterministic tests.
 * @returns Compact Schnorr proof `(challenge, response)`.
 */
export const createSchnorrProof = async (
    secret: bigint,
    statement: bigint,
    group: CryptoGroup,
    context: ProofContext,
    randomSource?: RandomBytesSource,
): Promise<SchnorrProof> => {
    assertProofContext(context, group);
    assertScalarInZq(secret, group.q);
    assertInSubgroup(statement, group.p, group.q);

    const nonce = await hedgedNonce(
        secret,
        nonceContext(statement, group, context),
        group,
        randomSource,
    );
    const commitment = modPowP(group.g, nonce, group.p);
    const challenge = await hashChallenge(
        challengePayload(statement, commitment, group, context),
        group.q,
    );

    return {
        challenge,
        response: modQ(nonce + secret * challenge, group.q),
    };
};

/**
 * Verifies a compact additive-form Schnorr proof.
 *
 * @param proof Compact Schnorr proof `(challenge, response)`.
 * @param statement Statement element `g^secret mod p`.
 * @param group Resolved group definition.
 * @param context Fiat-Shamir binding context.
 * @returns `true` when the proof verifies.
 */
export const verifySchnorrProof = async (
    proof: SchnorrProof,
    statement: bigint,
    group: CryptoGroup,
    context: ProofContext,
): Promise<boolean> => {
    assertProofContext(context, group);
    assertScalarInZq(proof.challenge, group.q);
    assertScalarInZq(proof.response, group.q);
    assertInSubgroup(statement, group.p, group.q);

    const commitment = modP(
        modPowP(group.g, proof.response, group.p) *
            modPowP(
                statement,
                negateExponent(proof.challenge, group.q),
                group.p,
            ),
        group.p,
    );
    const expected = await hashChallenge(
        challengePayload(statement, commitment, group, context),
        group.q,
    );

    return expected === proof.challenge;
};
