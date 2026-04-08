import { describe, expect, it } from 'vitest';

import {
    InvalidProofError,
    InvalidScalarError,
    getGroup,
    modPowP,
} from '#core';
import {
    createSchnorrProof,
    verifySchnorrProof,
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

describe('Schnorr proofs', () => {
    const group = getGroup(2048);
    const secret = 12345n;
    const statement = modPowP(group.g, secret, group.p);
    const context: ProofContext = {
        protocolVersion: 'v2',
        suiteId: group.name,
        manifestHash: 'manifest-1',
        sessionId: 'session-1',
        label: 'phase3-feldman',
        participantIndex: 2,
        coefficientIndex: 1,
    };

    it('verifies honest proofs', async () => {
        const proof = await createSchnorrProof(
            secret,
            statement,
            group,
            context,
            createDeterministicSource(),
        );

        await expect(
            verifySchnorrProof(proof, statement, group, context),
        ).resolves.toBe(true);
    });

    it('rejects wrong secrets, different statements, and different contexts', async () => {
        const wrongProof = await createSchnorrProof(
            secret + 1n,
            statement,
            group,
            context,
            createDeterministicSource(),
        );
        const honestProof = await createSchnorrProof(
            secret,
            statement,
            group,
            context,
            createDeterministicSource(),
        );

        await expect(
            verifySchnorrProof(wrongProof, statement, group, context),
        ).resolves.toBe(false);
        await expect(
            verifySchnorrProof(
                honestProof,
                modPowP(group.g, secret + 1n, group.p),
                group,
                context,
            ),
        ).resolves.toBe(false);
        await expect(
            verifySchnorrProof(honestProof, statement, group, {
                ...context,
                sessionId: 'session-2',
            }),
        ).resolves.toBe(false);
    });

    it('is deterministic for a fixed injected nonce source', async () => {
        const left = await createSchnorrProof(
            secret,
            statement,
            group,
            context,
            createDeterministicSource(),
        );
        const right = await createSchnorrProof(
            secret,
            statement,
            group,
            context,
            createDeterministicSource(),
        );

        expect(left).toEqual(right);
    });

    it('rejects malformed proof scalars and invalid contexts', async () => {
        const proof = await createSchnorrProof(
            secret,
            statement,
            group,
            context,
            createDeterministicSource(),
        );

        await expect(
            verifySchnorrProof(
                { ...proof, challenge: group.q },
                statement,
                group,
                context,
            ),
        ).rejects.toBeInstanceOf(InvalidScalarError);
        await expect(
            verifySchnorrProof(
                { ...proof, response: group.q },
                statement,
                group,
                context,
            ),
        ).rejects.toBeInstanceOf(InvalidScalarError);
        await expect(
            createSchnorrProof(
                secret,
                statement,
                group,
                { ...context, coefficientIndex: 0 },
                createDeterministicSource(),
            ),
        ).rejects.toBeInstanceOf(InvalidProofError);
    });
});
