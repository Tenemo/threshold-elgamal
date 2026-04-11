import { describe, expect, it } from 'vitest';

import { getGroup } from '#core';
import {
    encryptAdditiveWithRandomness,
    generateParametersWithPrivateKey,
} from '#elgamal';
import { createDisjunctiveProof, type ProofContext } from '#proofs';
import {
    canonicalUnsignedPayloadBytes,
    hashRosterEntries,
    verifyAndAggregateBallots,
    verifySignedProtocolPayloads,
    type BallotTranscriptEntry,
} from '#protocol';
import { mapChunked } from '#runtime';
import {
    decryptEnvelope,
    encryptEnvelope,
    exportAuthPublicKey,
    exportTransportPublicKey,
    generateAuthKeyPair,
    generateTransportKeyPair,
    isX25519Supported,
    resolveTransportSuite,
    signPayloadBytes,
} from '#transport';
const buildBrowserBallot = async (
    voterIndex: number,
    vote: bigint,
    randomness: bigint,
): Promise<BallotTranscriptEntry> => {
    const group = getGroup('ristretto255');
    const { publicKey } = generateParametersWithPrivateKey(123n);
    const ciphertext = encryptAdditiveWithRandomness(
        vote,
        publicKey,
        randomness,
        20n,
    );
    const context: ProofContext = {
        protocolVersion: 'v1',
        suiteId: group.name,
        manifestHash: 'manifest-hash',
        sessionId: 'session-1',
        label: 'ballot-range-proof',
        voterIndex,
        optionIndex: 1,
    };
    return {
        voterIndex,
        optionIndex: 1,
        ciphertext,
        proof: await createDisjunctiveProof(
            vote,
            randomness,
            ciphertext,
            publicKey,
            [1n, 2n, 3n],
            group,
            context,
        ),
    };
};
describe('browser runtime coverage', () => {
    it('verifies roster signatures, ballot proofs, and chunked browser work', async () => {
        expect(window).toBeDefined();
        expect(crypto.subtle).toBeDefined();
        const auth = await generateAuthKeyPair();
        const transport = await generateTransportKeyPair({ suite: 'P-256' });
        const authPublicKey = await exportAuthPublicKey(auth.publicKey);
        const transportPublicKey = await exportTransportPublicKey(
            transport.publicKey,
        );
        const rosterHash = await hashRosterEntries([
            {
                participantIndex: 1,
                authPublicKey,
                transportPublicKey,
            },
        ]);
        const registration = {
            sessionId: 'session-1',
            manifestHash: 'manifest-1',
            phase: 0,
            participantIndex: 1,
            messageType: 'registration' as const,
            rosterHash,
            authPublicKey,
            transportPublicKey,
        };
        const acceptance = {
            sessionId: 'session-1',
            manifestHash: 'manifest-1',
            phase: 0,
            participantIndex: 1,
            messageType: 'manifest-acceptance' as const,
            rosterHash,
            assignedParticipantIndex: 1,
        };
        await expect(
            verifySignedProtocolPayloads(
                [
                    {
                        payload: registration,
                        signature: await signPayloadBytes(
                            auth.privateKey,
                            canonicalUnsignedPayloadBytes(registration),
                        ),
                    },
                    {
                        payload: acceptance,
                        signature: await signPayloadBytes(
                            auth.privateKey,
                            canonicalUnsignedPayloadBytes(acceptance),
                        ),
                    },
                ],
                1,
            ),
        ).resolves.toMatchObject({
            rosterHash,
        });
        const { publicKey } = generateParametersWithPrivateKey(123n);
        const ballots = await mapChunked(
            [
                [2, 7],
                [1, 5],
                [3, 9],
            ] as const,
            async ([vote, randomness], index) =>
                buildBrowserBallot(index + 1, BigInt(vote), BigInt(randomness)),
            {
                chunkSize: 1,
            },
        );
        const verified = await verifyAndAggregateBallots({
            ballots,
            publicKey,
            validValues: [1n, 2n, 3n],
            protocolVersion: 'v1',
            manifestHash: 'manifest-hash',
            sessionId: 'session-1',
        });
        expect(verified.ballots.map((ballot) => ballot.voterIndex)).toEqual([
            1, 2, 3,
        ]);
        expect(verified.aggregate.ballotCount).toBe(3);
        expect(verified.transcriptHash).toHaveLength(64);
    });
    it('resolves the preferred transport suite and round-trips browser envelopes', async () => {
        const resolvedSuite = await resolveTransportSuite();
        expect(resolvedSuite).toBe(
            (await isX25519Supported()) ? 'X25519' : 'P-256',
        );
        const recipient = await generateTransportKeyPair({
            suite: resolvedSuite,
        });
        const recipientPublicKey = await exportTransportPublicKey(
            recipient.publicKey,
        );
        const plaintext = new TextEncoder().encode('browser-envelope');
        const { envelope } = await encryptEnvelope(
            plaintext,
            recipientPublicKey,
            {
                sessionId: 'session-1',
                phase: 1,
                dealerIndex: 1,
                recipientIndex: 2,
                envelopeId: 'env-1-2',
                payloadType: 'dkg-share',
                protocolVersion: 'v1',
                rosterHash: 'roster-hash',
                suite: resolvedSuite,
            },
        );
        const decrypted = await decryptEnvelope(envelope, recipient.privateKey);
        expect(new TextDecoder().decode(decrypted)).toBe('browser-envelope');
    });
});
