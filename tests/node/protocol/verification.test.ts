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
    type ManifestAcceptancePayload,
    type RegistrationPayload,
    type SignedPayload,
} from '#protocol';
import {
    exportAuthPublicKey,
    exportTransportPublicKey,
    generateAuthKeyPair,
    generateTransportKeyPair,
    signPayloadBytes,
} from '#transport';

const signProtocolPayload = async <
    TPayload extends RegistrationPayload | ManifestAcceptancePayload,
>(
    privateKey: CryptoKey,
    payload: TPayload,
): Promise<SignedPayload<TPayload>> => ({
    payload,
    signature: await signPayloadBytes(
        privateKey,
        canonicalUnsignedPayloadBytes(payload),
    ),
});

const buildBallot = async (
    voterIndex: number,
    optionIndex: number,
    vote: bigint,
    randomness: bigint,
): Promise<BallotTranscriptEntry> => {
    const group = getGroup('ffdhe2048');
    const { publicKey } = generateParametersWithPrivateKey(123n, group.name);
    const ciphertext = encryptAdditiveWithRandomness(
        vote,
        publicKey,
        randomness,
        20n,
        group.name,
    );
    const context: ProofContext = {
        protocolVersion: 'v2',
        suiteId: group.name,
        manifestHash: 'manifest-hash',
        sessionId: 'session-1',
        label: 'ballot-range-proof',
        voterIndex,
        optionIndex,
    };

    return {
        voterIndex,
        optionIndex,
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

describe('protocol verification helpers', () => {
    it('verifies signed protocol payloads against the frozen roster', async () => {
        const authOne = await generateAuthKeyPair();
        const authTwo = await generateAuthKeyPair();
        const transportOne = await generateTransportKeyPair({ suite: 'P-256' });
        const transportTwo = await generateTransportKeyPair({ suite: 'P-256' });
        const rosterEntries = [
            {
                participantIndex: 2,
                authPublicKey: await exportAuthPublicKey(authTwo.publicKey),
                transportPublicKey: await exportTransportPublicKey(
                    transportTwo.publicKey,
                ),
            },
            {
                participantIndex: 1,
                authPublicKey: await exportAuthPublicKey(authOne.publicKey),
                transportPublicKey: await exportTransportPublicKey(
                    transportOne.publicKey,
                ),
            },
        ] as const;
        const rosterHash = await hashRosterEntries(rosterEntries);

        const transcript = [
            await signProtocolPayload(authTwo.privateKey, {
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 0,
                participantIndex: 2,
                messageType: 'registration',
                rosterHash,
                authPublicKey: rosterEntries[0].authPublicKey,
                transportPublicKey: rosterEntries[0].transportPublicKey,
            }),
            await signProtocolPayload(authOne.privateKey, {
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 0,
                participantIndex: 1,
                messageType: 'registration',
                rosterHash,
                authPublicKey: rosterEntries[1].authPublicKey,
                transportPublicKey: rosterEntries[1].transportPublicKey,
            }),
            await signProtocolPayload(authTwo.privateKey, {
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 0,
                participantIndex: 2,
                messageType: 'manifest-acceptance',
                rosterHash,
                assignedParticipantIndex: 2,
            }),
            await signProtocolPayload(authOne.privateKey, {
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 0,
                participantIndex: 1,
                messageType: 'manifest-acceptance',
                rosterHash,
                assignedParticipantIndex: 1,
            }),
        ] as const;

        const verified = await verifySignedProtocolPayloads(transcript, 2);

        expect(verified.rosterHash).toBe(rosterHash);
        expect(
            verified.rosterEntries.map((entry) => entry.participantIndex),
        ).toEqual([1, 2]);
        expect(
            verified.registrations.map(
                (registration) => registration.payload.participantIndex,
            ),
        ).toEqual([2, 1]);
    });

    it('rejects tampered payload signatures and roster mismatches', async () => {
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
        const registration = await signProtocolPayload(auth.privateKey, {
            sessionId: 'session-1',
            manifestHash: 'manifest-1',
            phase: 0,
            participantIndex: 1,
            messageType: 'registration',
            rosterHash,
            authPublicKey,
            transportPublicKey,
        });
        const acceptance = await signProtocolPayload(auth.privateKey, {
            sessionId: 'session-1',
            manifestHash: 'manifest-1',
            phase: 0,
            participantIndex: 1,
            messageType: 'manifest-acceptance',
            rosterHash,
            assignedParticipantIndex: 1,
        });

        await expect(
            verifySignedProtocolPayloads(
                [
                    registration,
                    {
                        ...acceptance,
                        payload: {
                            ...acceptance.payload,
                            assignedParticipantIndex: 2,
                        },
                    },
                ],
                1,
            ),
        ).rejects.toThrow(
            'Payload signature failed verification for participant 1 (manifest-acceptance)',
        );

        await expect(
            verifySignedProtocolPayloads(
                [
                    {
                        ...registration,
                        payload: {
                            ...registration.payload,
                            rosterHash: 'other-roster-hash',
                        },
                    },
                ],
                1,
            ),
        ).rejects.toThrow(
            'Registration signature failed verification for participant 1',
        );
    });

    it(
        'recomputes ballot aggregates deterministically and exposes dropped ballots',
        {
            timeout: 20_000,
        },
        async () => {
            const group = getGroup('ffdhe2048');
            const { publicKey } = generateParametersWithPrivateKey(
                123n,
                group.name,
            );
            const ballots = [
                await buildBallot(3, 1, 3n, 11n),
                await buildBallot(1, 1, 1n, 7n),
                await buildBallot(2, 1, 2n, 9n),
            ] as const;

            const verified = await verifyAndAggregateBallots({
                ballots,
                publicKey,
                validValues: [1n, 2n, 3n],
                group,
                manifestHash: 'manifest-hash',
                sessionId: 'session-1',
                minimumBallotCount: 2,
            });
            const reversed = await verifyAndAggregateBallots({
                ballots: [...ballots].reverse(),
                publicKey,
                validValues: [1n, 2n, 3n],
                group,
                manifestHash: 'manifest-hash',
                sessionId: 'session-1',
                minimumBallotCount: 2,
            });
            const partial = await verifyAndAggregateBallots({
                ballots: ballots.slice(0, 2),
                publicKey,
                validValues: [1n, 2n, 3n],
                group,
                manifestHash: 'manifest-hash',
                sessionId: 'session-1',
                minimumBallotCount: 2,
            });

            expect(verified.ballots.map((ballot) => ballot.voterIndex)).toEqual(
                [1, 2, 3],
            );
            expect(reversed.aggregate).toEqual(verified.aggregate);
            expect(reversed.transcriptHash).toBe(verified.transcriptHash);
            expect(partial.aggregate.ballotCount).toBe(2);
            expect(partial.aggregate.ciphertext).not.toEqual(
                verified.aggregate.ciphertext,
            );
        },
    );

    it('rejects duplicate ballot slots, wrong voter bindings, and publication-threshold underflows', async () => {
        const group = getGroup('ffdhe2048');
        const { publicKey } = generateParametersWithPrivateKey(
            123n,
            group.name,
        );
        const honestBallot = await buildBallot(1, 1, 2n, 5n);
        const secondBallot = await buildBallot(2, 1, 1n, 6n);

        await expect(
            verifyAndAggregateBallots({
                ballots: [honestBallot, { ...secondBallot, voterIndex: 1 }],
                publicKey,
                validValues: [1n, 2n, 3n],
                group,
                manifestHash: 'manifest-hash',
                sessionId: 'session-1',
                minimumBallotCount: 1,
            }),
        ).rejects.toThrow('Duplicate ballot slot 1:1 is not allowed');

        await expect(
            verifyAndAggregateBallots({
                ballots: [{ ...honestBallot, voterIndex: 3 }],
                publicKey,
                validValues: [1n, 2n, 3n],
                group,
                manifestHash: 'manifest-hash',
                sessionId: 'session-1',
                minimumBallotCount: 1,
            }),
        ).rejects.toThrow(
            'Ballot proof failed verification for voter 3 option 1',
        );

        await expect(
            verifyAndAggregateBallots({
                ballots: [honestBallot, secondBallot],
                publicKey,
                validValues: [1n, 2n, 3n],
                group,
                manifestHash: 'manifest-hash',
                sessionId: 'session-1',
                minimumBallotCount: 3,
            }),
        ).rejects.toThrow(
            'Accepted ballot count 2 is below the minimum publication threshold 3',
        );
    });
});
