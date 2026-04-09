import {
    assertInSubgroup,
    assertInSubgroupOrIdentity,
    assertScalarInZq,
    fixedBaseModPow,
    multiExponentiate,
    modQ,
    type CryptoGroup,
    type RandomBytesSource,
} from '../core/index.js';
import type { ElgamalCiphertext } from '../elgamal/types.js';
import { encodeForChallenge } from '../serialize/index.js';

import {
    assertProofContext,
    contextElements,
    fixed,
    hashChallenge,
    negateExponent,
} from './helpers.js';
import { hedgedNonce } from './nonces.js';
import type { DLEQProof, ProofContext } from './types.js';

/** Statement tuple for a Chaum-Pedersen equality-of-discrete-logs proof. */
export type DLEQStatement = {
    /** Transcript-derived trustee verification key. */
    readonly publicKey: bigint;
    /** Ciphertext being partially decrypted. */
    readonly ciphertext: ElgamalCiphertext;
    /** Partial decryption share `d_j = c1^{x_j} mod p`. */
    readonly decryptionShare: bigint;
};

const nonceContext = (
    statement: DLEQStatement,
    group: CryptoGroup,
    context: ProofContext,
): Uint8Array =>
    encodeForChallenge(
        ...contextElements(context),
        fixed(group.g, group),
        fixed(statement.ciphertext.c1, group),
        fixed(statement.ciphertext.c2, group),
        fixed(statement.publicKey, group),
        fixed(statement.decryptionShare, group),
    );

const challengePayload = (
    statement: DLEQStatement,
    a1: bigint,
    a2: bigint,
    group: CryptoGroup,
    context: ProofContext,
): Uint8Array =>
    encodeForChallenge(
        ...contextElements(context),
        fixed(group.g, group),
        fixed(statement.ciphertext.c1, group),
        fixed(statement.ciphertext.c2, group),
        fixed(statement.publicKey, group),
        fixed(statement.decryptionShare, group),
        fixed(a1, group),
        fixed(a2, group),
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
    assertInSubgroup(statement.publicKey, group.p, group.q);
    assertInSubgroup(statement.ciphertext.c1, group.p, group.q);
    assertInSubgroupOrIdentity(statement.ciphertext.c2, group.p, group.q);
    assertInSubgroupOrIdentity(statement.decryptionShare, group.p, group.q);

    const nonce = await hedgedNonce(
        secret,
        nonceContext(statement, group, context),
        group,
        randomSource,
    );
    const a1 = fixedBaseModPow(group.g, nonce, group.p);
    const a2 = fixedBaseModPow(statement.ciphertext.c1, nonce, group.p);
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
    assertInSubgroup(statement.publicKey, group.p, group.q);
    assertInSubgroup(statement.ciphertext.c1, group.p, group.q);
    assertInSubgroupOrIdentity(statement.ciphertext.c2, group.p, group.q);
    assertInSubgroupOrIdentity(statement.decryptionShare, group.p, group.q);

    const a1 = multiExponentiate(
        [
            { base: group.g, exponent: proof.response },
            {
                base: statement.publicKey,
                exponent: negateExponent(proof.challenge, group.q),
            },
        ],
        group.p,
    );
    const a2 = multiExponentiate(
        [
            { base: statement.ciphertext.c1, exponent: proof.response },
            {
                base: statement.decryptionShare,
                exponent: negateExponent(proof.challenge, group.q),
            },
        ],
        group.p,
    );
    const expected = await hashChallenge(
        challengePayload(statement, a1, a2, group, context),
        group.q,
    );

    return expected === proof.challenge;
};
