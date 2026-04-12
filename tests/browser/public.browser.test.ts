import { describe, expect, it } from 'vitest';

import {
    combineDecryptionShares,
    createBallotClosePayload,
    createDLEQProof,
    createDecryptionShare,
    createDecryptionSharePayload,
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
    RISTRETTO_GROUP,
    SHIPPED_PROTOCOL_VERSION,
    scoreVotingDomain,
    type EncodedPoint,
    verifyDLEQProof,
} from '#root';

const asEncodedPoint = (value: string): EncodedPoint => value as EncodedPoint;

const thresholdVector = {
    ciphertext: {
        c1: asEncodedPoint(
            'f03aa76fb871dc237db54ddd77b91430a7876beb99ae7f4047545d6cd086101c',
        ),
        c2: asEncodedPoint(
            '805351278c30580bf6341232ffde49aab9b53b47f63c9049c16789b7fc38a83d',
        ),
    },
    sharePublicKey: asEncodedPoint(
        '760df7732237a40d6c5d7c5c2f19eefb7eea951648f33465bef5fa222c667a0e',
    ),
    subsetShares: [
        {
            index: 1,
            value: 93814n,
            decryptionShare: asEncodedPoint(
                'd4d45a7b49b6885c4517095b505cc78e59c838b94cc52d9277ff4c37cc5c9964',
            ),
        },
        {
            index: 3,
            value: 338226n,
            decryptionShare: asEncodedPoint(
                'fce0b2c12661c0c6425f663f701717092429245ecbc90d61389aefc50063da5a',
            ),
        },
        {
            index: 5,
            value: 691270n,
            decryptionShare: asEncodedPoint(
                'a6218d12d1912db37e0f6a69c664a50ef2663a8c24b91f48a125eeff72203e5f',
            ),
        },
    ],
} as const;

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
                countedParticipantIndices: [3, 1, 2],
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
        expect(ballotClose.payload.countedParticipantIndices).toEqual([
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

    it('builds the decryption-share reveal path through the root package only', async () => {
        const auth = await generateAuthKeyPair({ extractable: true });
        const computedShares = thresholdVector.subsetShares.map((share) =>
            createDecryptionShare(thresholdVector.ciphertext, share),
        );
        const participantThreeShare = computedShares[1];
        const proof = await createDLEQProof(
            thresholdVector.subsetShares[1].value,
            {
                publicKey: thresholdVector.sharePublicKey,
                ciphertext: thresholdVector.ciphertext,
                decryptionShare: participantThreeShare.value,
            },
            RISTRETTO_GROUP,
            {
                protocolVersion: SHIPPED_PROTOCOL_VERSION,
                suiteId: RISTRETTO_GROUP.name,
                manifestHash: 'aa'.repeat(32),
                sessionId: 'bb'.repeat(32),
                label: 'decryption-share-dleq',
                participantIndex: 3,
                optionIndex: 1,
            },
        );
        const signedPayload = await createDecryptionSharePayload(
            auth.privateKey,
            {
                sessionId: 'bb'.repeat(32),
                manifestHash: 'aa'.repeat(32),
                participantIndex: 3,
                optionIndex: 1,
                transcriptHash: 'cc'.repeat(32),
                ballotCount: 3,
                decryptionShare: participantThreeShare.value,
                proof,
            },
        );

        expect(computedShares).toEqual([
            {
                index: 1,
                value: thresholdVector.subsetShares[0].decryptionShare,
            },
            {
                index: 3,
                value: thresholdVector.subsetShares[1].decryptionShare,
            },
            {
                index: 5,
                value: thresholdVector.subsetShares[2].decryptionShare,
            },
        ]);
        await expect(
            verifyDLEQProof(
                proof,
                {
                    publicKey: thresholdVector.sharePublicKey,
                    ciphertext: thresholdVector.ciphertext,
                    decryptionShare: participantThreeShare.value,
                },
                RISTRETTO_GROUP,
                {
                    protocolVersion: SHIPPED_PROTOCOL_VERSION,
                    suiteId: RISTRETTO_GROUP.name,
                    manifestHash: 'aa'.repeat(32),
                    sessionId: 'bb'.repeat(32),
                    label: 'decryption-share-dleq',
                    participantIndex: 3,
                    optionIndex: 1,
                },
            ),
        ).resolves.toBe(true);
        expect(signedPayload.payload.decryptionShare).toBe(
            participantThreeShare.value,
        );
        expect(
            combineDecryptionShares(
                thresholdVector.ciphertext,
                computedShares,
                20n,
            ),
        ).toBe(13n);
    });
});
