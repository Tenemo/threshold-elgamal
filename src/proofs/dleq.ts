import {
    assertInSubgroup,
    assertInSubgroupOrIdentity,
    assertScalarInZq,
    modQ,
    type CryptoGroup,
    type RandomBytesSource,
} from '../core/index.js';
import {
    decodePoint,
    encodePoint,
    multiplyBase,
    pointMultiply,
    pointSubtract,
} from '../core/ristretto.js';
import type { ElgamalCiphertext } from '../elgamal/types.js';
import { encodeForChallenge } from '../serialize/index.js';

import {
    assertProofContext,
    contextElements,
    fixedPoint,
    hashChallenge,
} from './helpers.js';
import { hedgedNonce } from './nonces.js';
import type { DLEQProof, ProofContext } from './types.js';

/** Statement tuple for a Chaum-Pedersen equality-of-discrete-logs proof. */
export type DLEQStatement = {
    /** Transcript-derived trustee verification key. */
    readonly publicKey: string;
    /** Ciphertext being partially decrypted. */
    readonly ciphertext: ElgamalCiphertext;
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
 * @param secret Witness scalar.
 * @param statement DLEQ statement over `(g, publicKey)` and `(c1, share)`.
 * @param group Resolved group definition.
 * @param context Fiat-Shamir binding context.
 * @param randomSource Optional random source used for deterministic tests.
 * @returns Compact DLEQ proof `(challenge, response)`.
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
 * Verifies a compact additive-form Chaum-Pedersen proof of equal discrete logs.
 *
 * @param proof Compact DLEQ proof `(challenge, response)`.
 * @param statement DLEQ statement over `(g, publicKey)` and `(c1, share)`.
 * @param group Resolved group definition.
 * @param context Fiat-Shamir binding context.
 * @returns `true` when the proof verifies.
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
