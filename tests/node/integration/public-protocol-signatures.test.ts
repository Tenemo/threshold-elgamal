import { describe, expect, it } from 'vitest';

import {
    createRegistrationPayload,
    deriveSessionId,
    exportAuthPublicKey,
    exportTransportPublicKey,
    generateAuthKeyPair,
    generateTransportKeyPair,
    hashRosterEntries,
    SHIPPED_PROTOCOL_VERSION,
} from '#root';
import { signProtocolPayload } from '#src/protocol/public';
import { verifySignedProtocolPayloads } from '#src/protocol/verification';

const manifestHash = 'aa'.repeat(32);
const sessionId = 'bb'.repeat(32);

const createRegistrationFixture = async (input: {
    readonly authKeyPair: Awaited<ReturnType<typeof generateAuthKeyPair>>;
    readonly authPublicKey: Awaited<ReturnType<typeof exportAuthPublicKey>>;
    readonly participantIndex: number;
    readonly protocolVersion?: string;
    readonly rosterHash: string;
    readonly transportPublicKey: Awaited<
        ReturnType<typeof exportTransportPublicKey>
    >;
}): ReturnType<typeof createRegistrationPayload> =>
    createRegistrationPayload(input.authKeyPair.privateKey, {
        authPublicKey: input.authPublicKey,
        manifestHash,
        participantIndex: input.participantIndex,
        protocolVersion: input.protocolVersion,
        rosterHash: input.rosterHash,
        sessionId,
        transportPublicKey: input.transportPublicKey,
    });

describe('public protocol payload signatures', () => {
    it('defaults signed payloads to the shipped protocol version', async () => {
        const auth = await generateAuthKeyPair();
        const signedPayload = await signProtocolPayload(auth.privateKey, {
            sessionId,
            manifestHash,
            phase: 6,
            participantIndex: 1,
            messageType: 'ballot-close',
            countedParticipantIndices: [1],
        });

        expect(signedPayload.payload.protocolVersion).toBe(
            SHIPPED_PROTOCOL_VERSION,
        );
    });

    it('binds derived session ids to the protocol-version namespace', async () => {
        const shippedSessionId = await deriveSessionId(
            manifestHash,
            'cc'.repeat(32),
            'nonce',
            'timestamp',
        );
        const futureSessionId = await deriveSessionId(
            manifestHash,
            'cc'.repeat(32),
            'nonce',
            'timestamp',
            'v2',
        );

        expect(shippedSessionId).not.toBe(futureSessionId);
    });

    it('rejects duplicate auth public keys in roster hashing and transcript verification', async () => {
        const authOne = await generateAuthKeyPair();
        const authTwo = await generateAuthKeyPair();
        const transportOne = await generateTransportKeyPair();
        const transportTwo = await generateTransportKeyPair();
        const authOnePublicKey = await exportAuthPublicKey(authOne.publicKey);
        const authTwoPublicKey = await exportAuthPublicKey(authTwo.publicKey);
        const transportOnePublicKey = await exportTransportPublicKey(
            transportOne.publicKey,
        );
        const transportTwoPublicKey = await exportTransportPublicKey(
            transportTwo.publicKey,
        );

        await expect(
            hashRosterEntries([
                {
                    participantIndex: 1,
                    authPublicKey: authOnePublicKey,
                    transportPublicKey: transportOnePublicKey,
                },
                {
                    participantIndex: 2,
                    authPublicKey: authOnePublicKey,
                    transportPublicKey: transportTwoPublicKey,
                },
            ]),
        ).rejects.toThrow(
            'Duplicate roster auth public key for participants 1 and 2',
        );

        await expect(
            verifySignedProtocolPayloads([
                await createRegistrationFixture({
                    authKeyPair: authOne,
                    authPublicKey: authOnePublicKey,
                    participantIndex: 1,
                    rosterHash: 'dd'.repeat(32),
                    transportPublicKey: transportOnePublicKey,
                }),
                await createRegistrationFixture({
                    authKeyPair: authOne,
                    authPublicKey: authOnePublicKey,
                    participantIndex: 2,
                    rosterHash: 'dd'.repeat(32),
                    transportPublicKey: transportTwoPublicKey,
                }),
            ]),
        ).rejects.toThrow(
            'Duplicate roster auth public key for participants 1 and 2',
        );

        expect(authTwoPublicKey).not.toBe(authOnePublicKey);
    });

    it('rejects duplicate transport public keys in roster hashing and transcript verification', async () => {
        const authOne = await generateAuthKeyPair();
        const authTwo = await generateAuthKeyPair();
        const transportOne = await generateTransportKeyPair();
        const authOnePublicKey = await exportAuthPublicKey(authOne.publicKey);
        const authTwoPublicKey = await exportAuthPublicKey(authTwo.publicKey);
        const transportOnePublicKey = await exportTransportPublicKey(
            transportOne.publicKey,
        );

        await expect(
            hashRosterEntries([
                {
                    participantIndex: 1,
                    authPublicKey: authOnePublicKey,
                    transportPublicKey: transportOnePublicKey,
                },
                {
                    participantIndex: 2,
                    authPublicKey: authTwoPublicKey,
                    transportPublicKey: transportOnePublicKey,
                },
            ]),
        ).rejects.toThrow(
            'Duplicate roster transport public key for participants 1 and 2',
        );

        await expect(
            verifySignedProtocolPayloads([
                await createRegistrationFixture({
                    authKeyPair: authOne,
                    authPublicKey: authOnePublicKey,
                    participantIndex: 1,
                    rosterHash: 'ee'.repeat(32),
                    transportPublicKey: transportOnePublicKey,
                }),
                await createRegistrationFixture({
                    authKeyPair: authTwo,
                    authPublicKey: authTwoPublicKey,
                    participantIndex: 2,
                    rosterHash: 'ee'.repeat(32),
                    transportPublicKey: transportOnePublicKey,
                }),
            ]),
        ).rejects.toThrow(
            'Duplicate roster transport public key for participants 1 and 2',
        );
    });

    it('rejects non-shipped protocol versions even when signatures are otherwise valid', async () => {
        const auth = await generateAuthKeyPair();
        const transport = await generateTransportKeyPair();
        const authPublicKey = await exportAuthPublicKey(auth.publicKey);
        const transportPublicKey = await exportTransportPublicKey(
            transport.publicKey,
        );
        const registration = await createRegistrationFixture({
            authKeyPair: auth,
            authPublicKey,
            participantIndex: 1,
            protocolVersion: 'v2',
            rosterHash: 'ff'.repeat(32),
            transportPublicKey,
        });

        await expect(
            verifySignedProtocolPayloads([registration]),
        ).rejects.toThrow('Protocol payload version must equal v1');
    });
});
