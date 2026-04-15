/**
 * Schnorr proof helpers used for knowledge-of-discrete-log statements.
 *
 * In the supported workflow this is primarily used for Feldman coefficient
 * proofs inside the DKG transcript.
 */
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
import { encodeForChallenge } from '../serialize/encoding';

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
 * This is the proof format used when a trustee needs to show knowledge of a
 * secret coefficient without revealing it.
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
 * DKG transcript verification uses this to validate Feldman coefficient proofs
 * before accepting the published commitment set.
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
