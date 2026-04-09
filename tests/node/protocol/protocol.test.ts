import { describe, expect, it } from 'vitest';

import {
    canonicalUnsignedPayloadBytes,
    canonicalizeElectionManifest,
    canonicalizeJson,
    classifySlotConflict,
    compareProtocolPayloads,
    defaultMinimumPublicationThreshold,
    deriveSessionId,
    formatSessionFingerprint,
    hashElectionManifest,
    hashProtocolTranscript,
    payloadSlotKey,
    sortProtocolPayloads,
    type ElectionManifest,
    type ManifestAcceptancePayload,
    type RegistrationPayload,
    type SignedPayload,
} from '#protocol';

describe('protocol payloads and transcripts', () => {
    const manifest: ElectionManifest = {
        protocolVersion: 'v1',
        suiteId: 'ffdhe3072',
        threshold: 3,
        participantCount: 5,
        minimumPublicationThreshold: 4,
        allowAbstention: false,
        scoreDomainMin: 1,
        scoreDomainMax: 10,
        ballotFinality: 'first-valid',
        rosterHash: 'roster-hash',
        optionList: ['Alpha', 'Beta'],
        epochDeadlines: ['2026-04-08T12:00:00Z'],
    };
    const registration: RegistrationPayload = {
        sessionId: 'session-1',
        manifestHash: 'manifest-1',
        phase: 0,
        participantIndex: 2,
        messageType: 'registration',
        rosterHash: 'roster-hash',
        authPublicKey: 'auth-key',
        transportPublicKey: 'transport-key',
    };
    const acceptance: ManifestAcceptancePayload = {
        sessionId: 'session-1',
        manifestHash: 'manifest-1',
        phase: 0,
        participantIndex: 1,
        messageType: 'manifest-acceptance',
        rosterHash: 'roster-hash',
        assignedParticipantIndex: 1,
    };

    it('canonicalizes JSON with sorted keys and fixed-width bigint strings', () => {
        expect(
            canonicalizeJson(
                { b: 2n, a: 1n, nested: [{ z: 3n, y: 4n }] },
                { bigintByteLength: 2 },
            ),
        ).toBe('{"a":"0001","b":"0002","nested":[{"y":"0004","z":"0003"}]}');
    });

    it('canonicalizes and hashes manifests deterministically', async () => {
        expect(canonicalizeElectionManifest(manifest)).toBe(
            '{"allowAbstention":false,"ballotFinality":"first-valid","epochDeadlines":["2026-04-08T12:00:00Z"],"minimumPublicationThreshold":4,"optionList":["Alpha","Beta"],"participantCount":5,"protocolVersion":"v1","rosterHash":"roster-hash","scoreDomainMax":10,"scoreDomainMin":1,"suiteId":"ffdhe3072","threshold":3}',
        );

        await expect(hashElectionManifest(manifest)).resolves.toHaveLength(64);
        await expect(
            deriveSessionId('manifest-1', 'roster-1', 'nonce-1', 'ts-1'),
        ).resolves.toHaveLength(64);
    });

    it('derives the shipped publication floor as t plus two ballots', () => {
        expect(defaultMinimumPublicationThreshold(3, 5)).toBe(4);
        expect(defaultMinimumPublicationThreshold(26, 51)).toBe(27);
    });

    it('orders protocol payloads deterministically', () => {
        const sorted = sortProtocolPayloads([registration, acceptance]);

        expect(
            compareProtocolPayloads(registration, acceptance),
        ).toBeGreaterThan(0);
        expect(sorted).toEqual([acceptance, registration]);
    });

    it('uses slot-specific tie-breakers and canonical bytes for a total transcript order', async () => {
        const encryptedForSecond = {
            sessionId: 'session-1',
            manifestHash: 'manifest-1',
            phase: 1,
            participantIndex: 1,
            messageType: 'encrypted-dual-share' as const,
            recipientIndex: 2,
            envelopeId: 'env-1-2',
            suite: 'P-256' as const,
            ephemeralPublicKey: 'epk-a',
            iv: 'iv-a',
            ciphertext: 'ciphertext-a',
        };
        const encryptedForThird = {
            ...encryptedForSecond,
            recipientIndex: 3,
            envelopeId: 'env-1-3',
            ephemeralPublicKey: 'epk-b',
            iv: 'iv-b',
            ciphertext: 'ciphertext-b',
        };
        const equivocatedSecond = {
            ...encryptedForSecond,
            ciphertext: 'ciphertext-z',
        };

        expect(
            compareProtocolPayloads(encryptedForSecond, encryptedForThird),
        ).toBeLessThan(0);
        expect(
            compareProtocolPayloads(encryptedForSecond, equivocatedSecond),
        ).toBeLessThan(0);
        expect(
            sortProtocolPayloads([
                encryptedForThird,
                equivocatedSecond,
                encryptedForSecond,
            ]),
        ).toEqual([encryptedForSecond, equivocatedSecond, encryptedForThird]);

        const firstHash = await hashProtocolTranscript([
            encryptedForThird,
            encryptedForSecond,
        ]);
        const secondHash = await hashProtocolTranscript([
            encryptedForSecond,
            encryptedForThird,
        ]);

        expect(firstHash).toBe(secondHash);
    });

    it('derives canonical unsigned payload bytes and slot keys', () => {
        expect(
            Buffer.from(canonicalUnsignedPayloadBytes(registration)).toString(
                'utf8',
            ),
        ).toBe(
            '{"authPublicKey":"auth-key","manifestHash":"manifest-1","messageType":"registration","participantIndex":2,"phase":0,"rosterHash":"roster-hash","sessionId":"session-1","transportPublicKey":"transport-key"}',
        );
        expect(payloadSlotKey(registration)).toBe('session-1:0:2:registration');
    });

    it('uses recipient-aware slot keys for encrypted share payloads', () => {
        const left = {
            payload: {
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 1,
                participantIndex: 1,
                messageType: 'encrypted-dual-share' as const,
                recipientIndex: 2,
                envelopeId: 'env-1-2',
                suite: 'P-256' as const,
                ephemeralPublicKey: 'epk',
                iv: 'iv',
                ciphertext: 'ciphertext',
            },
            signature: 'aaaa',
        };
        const right = {
            payload: {
                ...left.payload,
                recipientIndex: 3,
                envelopeId: 'env-1-3',
            },
            signature: 'bbbb',
        };

        expect(payloadSlotKey(left.payload)).toBe(
            'session-1:1:1:encrypted-dual-share:2',
        );
        expect(payloadSlotKey(right.payload)).toBe(
            'session-1:1:1:encrypted-dual-share:3',
        );
        expect(classifySlotConflict(left, right)).toBe('distinct');
    });

    it('distinguishes complaint envelopes and dealer-specific share reveals', () => {
        const leftComplaint = {
            payload: {
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 2,
                participantIndex: 2,
                messageType: 'complaint' as const,
                dealerIndex: 5,
                envelopeId: 'env-5-2',
                reason: 'aes-gcm-failure' as const,
            },
            signature: 'aaaa',
        };
        const rightComplaint = {
            payload: {
                ...leftComplaint.payload,
                envelopeId: 'env-5-3',
            },
            signature: 'bbbb',
        };
        const reveal = {
            payload: {
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 3,
                participantIndex: 3,
                messageType: 'feldman-share-reveal' as const,
                dealerIndex: 5,
                shareValue: 'abcd',
            },
            signature: 'cccc',
        };
        const equivocatedReveal = {
            payload: {
                ...reveal.payload,
                shareValue: 'dcba',
            },
            signature: 'dddd',
        };

        expect(payloadSlotKey(leftComplaint.payload)).toBe(
            'session-1:2:2:complaint:5:env-5-2',
        );
        expect(payloadSlotKey(rightComplaint.payload)).toBe(
            'session-1:2:2:complaint:5:env-5-3',
        );
        expect(classifySlotConflict(leftComplaint, rightComplaint)).toBe(
            'distinct',
        );
        expect(payloadSlotKey(reveal.payload)).toBe(
            'session-1:3:3:feldman-share-reveal:5',
        );
        expect(classifySlotConflict(reveal, equivocatedReveal)).toBe(
            'equivocation',
        );
    });

    it('derives slot keys for complaint resolutions and typed voting payloads', () => {
        expect(
            payloadSlotKey({
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 2,
                participantIndex: 5,
                messageType: 'complaint-resolution',
                dealerIndex: 5,
                complainantIndex: 2,
                envelopeId: 'env-5-2',
                suite: 'P-256',
                revealedEphemeralPrivateKey: 'ephemeral-private-key',
            }),
        ).toBe('session-1:2:5:complaint-resolution:5:2:env-5-2');
        expect(
            payloadSlotKey({
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 5,
                participantIndex: 3,
                messageType: 'ballot-submission',
                optionIndex: 2,
                ciphertext: {
                    c1: '01',
                    c2: '02',
                },
                proof: {
                    branches: [
                        {
                            challenge: '03',
                            response: '04',
                        },
                    ],
                },
            }),
        ).toBe('session-1:5:3:ballot-submission:2');
        expect(
            payloadSlotKey({
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 6,
                participantIndex: 2,
                messageType: 'decryption-share',
                transcriptHash: 'aa'.repeat(32),
                ballotCount: 3,
                decryptionShare: '05',
                proof: {
                    challenge: '06',
                    response: '07',
                },
            }),
        ).toBe(`session-1:6:2:decryption-share:${'aa'.repeat(32)}`);
        expect(
            payloadSlotKey({
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 7,
                participantIndex: 1,
                messageType: 'tally-publication',
                transcriptHash: 'bb'.repeat(32),
                ballotCount: 3,
                tally: '08',
                decryptionParticipantIndices: [1, 3],
            }),
        ).toBe(`session-1:7:1:tally-publication:${'bb'.repeat(32)}`);
        expect(
            payloadSlotKey({
                sessionId: 'session-2',
                manifestHash: 'manifest-2',
                phase: 0,
                participantIndex: 1,
                messageType: 'ceremony-restart',
                previousSessionId: 'session-1',
                previousTranscriptHash: 'cc'.repeat(32),
                reason: 'timeout',
            }),
        ).toBe('session-2:0:1:ceremony-restart:session-1');
    });

    it('distinguishes idempotent retransmissions from equivocation', () => {
        const identicalUnsigned: SignedPayload = {
            payload: registration,
            signature: 'aaaa',
        };
        const resigned: SignedPayload = {
            payload: registration,
            signature: 'bbbb',
        };
        const equivocated: SignedPayload = {
            payload: { ...registration, transportPublicKey: 'other-key' },
            signature: 'cccc',
        };

        expect(classifySlotConflict(identicalUnsigned, resigned)).toBe(
            'idempotent',
        );
        expect(classifySlotConflict(identicalUnsigned, equivocated)).toBe(
            'equivocation',
        );
    });

    it('hashes transcripts and formats session fingerprints', async () => {
        const transcriptHash = await hashProtocolTranscript([
            registration,
            acceptance,
        ]);

        expect(transcriptHash).toHaveLength(64);
        expect(formatSessionFingerprint(transcriptHash)).toMatch(
            /^[0-9A-F]{4}(?:-[0-9A-F]{4}){7}$/,
        );
    });
});
