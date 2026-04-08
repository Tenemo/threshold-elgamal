import { describe, expect, it } from 'vitest';

import {
    InvalidProofError,
    InvalidScalarError,
    getGroup,
    modPowP,
} from '#core';
import { encryptAdditiveWithRandomness } from '#elgamal';
import {
    createDLEQProof,
    verifyDLEQProof,
    type DLEQStatement,
    type ProofContext,
} from '#proofs';

const createDeterministicSource = () => {
    let counter = 0;

    return (length: number): Uint8Array => {
        const bytes = new Uint8Array(length);
        for (let index = 0; index < length; index += 1) {
            bytes[index] = (counter + index) & 0xff;
        }
        counter = (counter + length) & 0xff;
        return bytes;
    };
};

describe('DLEQ proofs', () => {
    const group = getGroup(2048);
    const secret = 12345n;
    const publicKey = modPowP(group.g, secret, group.p);
    const ciphertext = encryptAdditiveWithRandomness(
        7n,
        publicKey,
        42n,
        20n,
        group.name,
    );
    const statement: DLEQStatement = {
        publicKey,
        ciphertext,
        decryptionShare: modPowP(ciphertext.c1, secret, group.p),
    };
    const context: ProofContext = {
        protocolVersion: 'v2',
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
            publicKey: modPowP(group.g, secret + 1n, group.p),
        };
        const otherCiphertext = encryptAdditiveWithRandomness(
            7n,
            publicKey,
            99n,
            20n,
            group.name,
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
