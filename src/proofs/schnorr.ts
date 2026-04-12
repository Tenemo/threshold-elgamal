import {
    assertInSubgroup,
    assertScalarInZq,
    modQ,
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
import { encodeForChallenge } from '../serialize/index';

import {
    assertProofContext,
    contextElements,
    fixedPoint,
    hashChallenge,
} from './helpers';
import { hedgedNonce } from './nonces';
import type { ProofContext, SchnorrProof } from './types';

const nonceContext = (
    statement: string,
    group: CryptoGroup,
    context: ProofContext,
): Uint8Array =>
    encodeForChallenge(
        ...contextElements(context),
        fixedPoint(group.g),
        fixedPoint(statement),
    );

const challengePayload = (
    statement: string,
    commitment: string,
    group: CryptoGroup,
    context: ProofContext,
): Uint8Array =>
    encodeForChallenge(
        ...contextElements(context),
        fixedPoint(group.g),
        fixedPoint(statement),
        fixedPoint(commitment),
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
    statement: string,
    group: CryptoGroup,
    context: ProofContext,
    randomSource?: RandomBytesSource,
): Promise<SchnorrProof> => {
    assertProofContext(context, group);
    assertScalarInZq(secret, group.q);
    assertInSubgroup(statement);

    const nonce = await hedgedNonce(
        secret,
        nonceContext(statement, group, context),
        group,
        randomSource,
    );
    const commitment = encodePoint(multiplyBase(nonce));
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
    statement: string,
    group: CryptoGroup,
    context: ProofContext,
): Promise<boolean> => {
    assertProofContext(context, group);
    assertScalarInZq(proof.challenge, group.q);
    assertScalarInZq(proof.response, group.q);
    assertInSubgroup(statement);

    const commitment = encodePoint(
        pointSubtract(
            multiplyBase(proof.response),
            pointMultiply(
                decodePoint(statement, 'Schnorr statement'),
                proof.challenge,
            ),
        ),
    );
    const expected = await hashChallenge(
        challengePayload(statement, commitment, group, context),
        group.q,
    );

    return expected === proof.challenge;
};
