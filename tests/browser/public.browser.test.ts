import {
    createBallotClosePayload,
    createElectionManifest,
    createManifestAcceptancePayload,
    createManifestPublicationPayload,
    createRegistrationPayload,
    createTallyPublicationPayload,
    decryptEnvelope,
    deriveSessionId,
    encryptEnvelope,
    exportAuthPublicKey,
    exportTransportPublicKey,
    generateAuthKeyPair,
    generateTransportKeyPair,
    hashElectionManifest,
    hashRosterEntries,
    scoreVotingDomain,
} from 'threshold-elgamal';

import { describe, expect, it } from 'vitest';

describe('browser public surface', () => {
    it('round-trips the shipped browser ceremony primitives through the root package', async () => {
        const participants = await Promise.all(
            Array.from({ length: 3 }, async (_value, offset) => {
                const index = offset + 1;
                const auth = await generateAuthKeyPair({ extractable: true });
                const transport = await generateTransportKeyPair({
                    extractable: true,
                });

                return {
                    auth,
                    index,
                    authPublicKey: await exportAuthPublicKey(auth.publicKey),
                    transport,
                    transportPublicKey: await exportTransportPublicKey(
                        transport.publicKey,
                    ),
                };
            }),
        );

        const rosterHash = await hashRosterEntries(
            participants.map((participant) => ({
                participantIndex: participant.index,
                authPublicKey: participant.authPublicKey,
                transportPublicKey: participant.transportPublicKey,
            })),
        );
        const manifest = createElectionManifest({
            rosterHash,
            optionList: ['Option 1', 'Option 2'],
        });
        const manifestHash = await hashElectionManifest(manifest);
        const sessionId = await deriveSessionId(
            manifestHash,
            rosterHash,
            'browser-smoke',
            '2026-04-11T12:00:00Z',
        );

        const manifestPublication = await createManifestPublicationPayload(
            participants[0].auth.privateKey,
            {
                manifest,
                manifestHash,
                participantIndex: participants[0].index,
                sessionId,
            },
        );
        const registration = await createRegistrationPayload(
            participants[1].auth.privateKey,
            {
                authPublicKey: participants[1].authPublicKey,
                manifestHash,
                participantIndex: participants[1].index,
                rosterHash,
                sessionId,
                transportPublicKey: participants[1].transportPublicKey,
            },
        );
        const acceptance = await createManifestAcceptancePayload(
            participants[2].auth.privateKey,
            {
                assignedParticipantIndex: participants[2].index,
                manifestHash,
                participantIndex: participants[2].index,
                rosterHash,
                sessionId,
            },
        );
        const ballotClose = await createBallotClosePayload(
            participants[0].auth.privateKey,
            {
                sessionId,
                manifestHash,
                participantIndex: participants[0].index,
                includedParticipantIndices: [3, 1, 2],
            },
        );
        const tallyPublication = await createTallyPublicationPayload(
            participants[0].auth.privateKey,
            {
                sessionId,
                manifestHash,
                participantIndex: participants[0].index,
                optionIndex: 1,
                transcriptHash: 'aa'.repeat(32),
                ballotCount: 3,
                decryptionParticipantIndices: [3, 1, 2],
                tally: 16n,
            },
        );
        const plaintext = new TextEncoder().encode('browser-envelope');
        const encrypted = await encryptEnvelope(
            plaintext,
            participants[1].transportPublicKey,
            {
                sessionId,
                rosterHash,
                phase: 1,
                dealerIndex: 1,
                recipientIndex: 2,
                envelopeId: 'env-1-2',
                payloadType: 'encrypted-dual-share',
                protocolVersion: 'v1',
                suite: 'X25519',
            },
        );
        const decrypted = await decryptEnvelope(
            encrypted.envelope,
            participants[1].transport.privateKey,
        );

        expect(manifestPublication.payload.messageType).toBe(
            'manifest-publication',
        );
        expect(registration.payload.messageType).toBe('registration');
        expect(acceptance.payload.messageType).toBe('manifest-acceptance');
        expect(ballotClose.payload.includedParticipantIndices).toEqual([
            1, 2, 3,
        ]);
        expect(tallyPublication.payload.decryptionParticipantIndices).toEqual([
            1, 2, 3,
        ]);
        expect(new TextDecoder().decode(decrypted)).toBe('browser-envelope');
        expect(scoreVotingDomain()).toEqual([
            1n,
            2n,
            3n,
            4n,
            5n,
            6n,
            7n,
            8n,
            9n,
            10n,
        ]);
    });

    it('rejects duplicate decryption participant indices in tally publication payloads', async () => {
        const auth = await generateAuthKeyPair({ extractable: true });

        await expect(
            createTallyPublicationPayload(auth.privateKey, {
                sessionId: 'session',
                manifestHash: 'aa'.repeat(32),
                participantIndex: 1,
                optionIndex: 1,
                transcriptHash: 'bb'.repeat(32),
                ballotCount: 3,
                decryptionParticipantIndices: [1, 2, 2],
                tally: 7n,
            }),
        ).rejects.toThrow('Decryption participant indices must be unique');
    });
});
