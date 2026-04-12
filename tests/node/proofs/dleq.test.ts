import { describe, expect, it } from 'vitest';

import { createDeterministicSource } from '../../../tools/internal/deterministic.js';

import { InvalidProofError, InvalidScalarError, RISTRETTO_GROUP } from '#core';
import { encryptAdditiveWithRandomness } from '#elgamal';
import {
    createDLEQProof,
    verifyDLEQProof,
    type DLEQStatement,
    type ProofContext,
} from '#proofs';
import {
    decodePoint,
    encodePoint,
    multiplyBase,
    pointMultiply,
} from '#src/core/ristretto';
describe('DLEQ proofs', () => {
    const group = RISTRETTO_GROUP;
    const secret = 12345n;
    const publicKey = encodePoint(multiplyBase(secret));
    const ciphertext = encryptAdditiveWithRandomness(7n, publicKey, 42n, 20n);
    const statement: DLEQStatement = {
        publicKey,
        ciphertext,
        decryptionShare: encodePoint(
            pointMultiply(decodePoint(ciphertext.c1), secret),
        ),
    };
    const context: ProofContext = {
        protocolVersion: 'v1',
        suiteId: group.name,
        manifestHash: 'manifest-1',
        sessionId: 'session-1',
        label: 'decryption-dleq',
        participantIndex: 2,
    };
    it('verifies honest DLEQ proofs', async () => {
        const proof = await createDLEQProof(
            secret,
            statement,
            group,
            context,
            createDeterministicSource(),
        );
        await expect(
            verifyDLEQProof(proof, statement, group, context),
        ).resolves.toBe(true);
    });
    it('rejects wrong secrets, forged verification keys, and cross-ciphertext replay', async () => {
        const proof = await createDLEQProof(
            secret,
            statement,
            group,
            context,
            createDeterministicSource(),
        );
        const wrongProof = await createDLEQProof(
            secret + 1n,
            statement,
            group,
            context,
            createDeterministicSource(),
        );
        const forgedKeyStatement: DLEQStatement = {
            ...statement,
            publicKey: encodePoint(multiplyBase(secret + 1n)),
        };
        const otherCiphertext = encryptAdditiveWithRandomness(
            7n,
            publicKey,
            99n,
            20n,
        );
        await expect(
            verifyDLEQProof(wrongProof, statement, group, context),
        ).resolves.toBe(false);
        await expect(
            verifyDLEQProof(proof, forgedKeyStatement, group, context),
        ).resolves.toBe(false);
        await expect(
            verifyDLEQProof(
                proof,
                { ...statement, ciphertext: otherCiphertext },
                group,
                context,
            ),
        ).resolves.toBe(false);
        await expect(
            verifyDLEQProof(proof, statement, group, {
                ...context,
                participantIndex: undefined,
                coefficientIndex: context.participantIndex,
            }),
        ).resolves.toBe(false);
    });
    it('rejects malformed proof scalars and invalid contexts', async () => {
        const proof = await createDLEQProof(
            secret,
            statement,
            group,
            context,
            createDeterministicSource(),
        );
        await expect(
            verifyDLEQProof(
                { ...proof, challenge: group.q },
                statement,
                group,
                context,
            ),
        ).rejects.toBeInstanceOf(InvalidScalarError);
        await expect(
            verifyDLEQProof(
                { ...proof, response: group.q },
                statement,
                group,
                context,
            ),
        ).rejects.toBeInstanceOf(InvalidScalarError);
        await expect(
            createDLEQProof(
                secret,
                statement,
                group,
                { ...context, participantIndex: 0 },
                createDeterministicSource(),
            ),
        ).rejects.toBeInstanceOf(InvalidProofError);
    });
});
