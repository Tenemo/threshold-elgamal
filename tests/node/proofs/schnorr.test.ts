import { describe, expect, it } from 'vitest';

import { createDeterministicSource } from '../../helpers/deterministic';

import { InvalidProofError, InvalidScalarError, RISTRETTO_GROUP } from '#core';
import {
    createSchnorrProof,
    verifySchnorrProof,
    type ProofContext,
} from '#root';
import { encodePoint, multiplyBase } from '#src/core/ristretto';

describe('Schnorr proofs', () => {
    const group = RISTRETTO_GROUP;
    const secret = 12345n;
    const statement = encodePoint(multiplyBase(secret));
    const context: ProofContext = {
        protocolVersion: 'v1',
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
                encodePoint(multiplyBase(secret + 1n)),
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
        await expect(
            verifySchnorrProof(honestProof, statement, group, {
                ...context,
                participantIndex: undefined,
                coefficientIndex: context.participantIndex,
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

    it('rejects altered group definitions instead of silently accepting them', async () => {
        const alteredGroup = {
            ...group,
            g: group.h,
        };

        await expect(
            createSchnorrProof(
                secret,
                statement,
                alteredGroup,
                context,
                createDeterministicSource(),
            ),
        ).rejects.toBeInstanceOf(InvalidProofError);
    });
});
