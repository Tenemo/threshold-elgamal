/**
 * Chaum-Pedersen equality-of-discrete-logs proofs used for threshold
 * decryption-share publication and verification.
 */
import {
    assertInSubgroup,
    assertInSubgroupOrIdentity,
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
import type { ElGamalCiphertext } from '../elgamal/types';
import { encodeForChallenge } from '../serialize/encoding';

import {
    assertProofContext,
    contextElements,
    fixedPoint,
    hashChallenge,
} from './helpers';
import { hedgedNonce } from './nonces';
import type { DLEQProof, ProofContext } from './types';

/**
 * Statement tuple for a Chaum-Pedersen equality-of-discrete-logs proof.
 *
 * In the supported voting flow this statement ties a trustee's decryption
 * share to both the joint public key and the accepted aggregate ciphertext.
 */
export type DLEQStatement = {
    /** Transcript-derived trustee verification key. */
    readonly publicKey: string;
    /** Ciphertext being partially decrypted. */
    readonly ciphertext: ElGamalCiphertext;
    /** Partial decryption share `d_j = c1^{x_j} mod p`. */
    readonly decryptionShare: string;
};

const nonceContext = (
    statement: DLEQStatement,
    group: CryptoGroup,
    context: ProofContext,
): Uint8Array =>
    encodeForChallenge(
        ...contextElements(context),
        fixedPoint(group.g),
        fixedPoint(statement.ciphertext.c1),
        fixedPoint(statement.ciphertext.c2),
        fixedPoint(statement.publicKey),
        fixedPoint(statement.decryptionShare),
    );

const challengePayload = (
    statement: DLEQStatement,
    a1: string,
    a2: string,
    group: CryptoGroup,
    context: ProofContext,
): Uint8Array =>
    encodeForChallenge(
        ...contextElements(context),
        fixedPoint(group.g),
        fixedPoint(statement.ciphertext.c1),
        fixedPoint(statement.ciphertext.c2),
        fixedPoint(statement.publicKey),
        fixedPoint(statement.decryptionShare),
        fixedPoint(a1),
        fixedPoint(a2),
    );

/**
 * Creates a compact additive-form Chaum-Pedersen proof of equal discrete logs.
 *
 * This is the proof published alongside each threshold decryption share so
 * observers can verify that the share came from the same secret exponent as the
 * trustee's transcript-derived verification key.
 */
export const createDLEQProof = async (
    secret: bigint,
    statement: DLEQStatement,
    group: CryptoGroup,
    context: ProofContext,
    randomSource?: RandomBytesSource,
): Promise<DLEQProof> => {
    assertProofContext(context, group);
    assertScalarInZq(secret, group.q);
    assertInSubgroup(statement.publicKey);
    assertInSubgroup(statement.ciphertext.c1);
    assertInSubgroupOrIdentity(statement.ciphertext.c2);
    assertInSubgroupOrIdentity(statement.decryptionShare);

    const nonce = await hedgedNonce(
        secret,
        nonceContext(statement, group, context),
        group,
        randomSource,
    );
    const a1 = encodePoint(multiplyBase(nonce));
    const a2 = encodePoint(
        pointMultiply(
            decodePoint(statement.ciphertext.c1, 'Ciphertext c1'),
            nonce,
        ),
    );
    const challenge = await hashChallenge(
        challengePayload(statement, a1, a2, group, context),
        group.q,
    );

    return {
        challenge,
        response: modQ(nonce + secret * challenge, group.q),
    };
};

/**
 * Verifies a compact additive-form Chaum-Pedersen proof of equal discrete
 * logs.
 *
 * Decryption-share verification routes through this helper after reconstructing
 * the transcript-bound proof statement for one option slot.
 */
export const verifyDLEQProof = async (
    proof: DLEQProof,
    statement: DLEQStatement,
    group: CryptoGroup,
    context: ProofContext,
): Promise<boolean> => {
    assertProofContext(context, group);
    assertScalarInZq(proof.challenge, group.q);
    assertScalarInZq(proof.response, group.q);
    assertInSubgroup(statement.publicKey);
    assertInSubgroup(statement.ciphertext.c1);
    assertInSubgroupOrIdentity(statement.ciphertext.c2);
    assertInSubgroupOrIdentity(statement.decryptionShare);

    const a1 = encodePoint(
        pointSubtract(
            multiplyBase(proof.response),
            pointMultiply(
                decodePoint(statement.publicKey, 'DLEQ public key'),
                proof.challenge,
            ),
        ),
    );
    const a2 = encodePoint(
        pointSubtract(
            pointMultiply(
                decodePoint(statement.ciphertext.c1, 'Ciphertext c1'),
                proof.response,
            ),
            pointMultiply(
                decodePoint(
                    statement.decryptionShare,
                    'Decryption share statement',
                ),
                proof.challenge,
            ),
        ),
    );
    const expected = await hashChallenge(
        challengePayload(statement, a1, a2, group, context),
        group.q,
    );

    return expected === proof.challenge;
};
