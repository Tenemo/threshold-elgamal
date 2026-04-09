import { signPayload } from './common.js';
import type { ParticipantRuntime, VotingFlowScenario } from './types.js';

import { majorityThreshold, type CryptoGroup } from '#core';
import {
    defaultMinimumPublicationThreshold,
    type ElectionManifest,
    type ManifestAcceptancePayload,
    type RegistrationPayload,
    type SignedPayload,
} from '#protocol';
import {
    exportAuthPublicKey,
    exportTransportPublicKey,
    generateAuthKeyPair,
    generateTransportKeyPair,
    type KeyAgreementSuite,
} from '#transport';

export const createParticipants = async (
    participantCount: number,
    transportSuite: KeyAgreementSuite,
): Promise<readonly ParticipantRuntime[]> =>
    Promise.all(
        Array.from({ length: participantCount }, async (_value, offset) => {
            const index = offset + 1;
            const auth = await generateAuthKeyPair();
            const transport = await generateTransportKeyPair({
                suite: transportSuite,
                extractable: true,
            });

            return {
                index,
                auth,
                authPublicKeyHex: await exportAuthPublicKey(auth.publicKey),
                transportPrivateKey: transport.privateKey,
                transportPublicKeyHex: await exportTransportPublicKey(
                    transport.publicKey,
                ),
                transportSuite: transport.suite,
            };
        }),
    );

export const buildManifest = (
    rosterHash: string,
    group: CryptoGroup,
    scenario: VotingFlowScenario,
): ElectionManifest => ({
    protocolVersion: 'v1',
    suiteId: group.name,
    threshold: majorityThreshold(scenario.participantCount),
    participantCount: scenario.participantCount,
    minimumPublicationThreshold: defaultMinimumPublicationThreshold(
        majorityThreshold(scenario.participantCount),
        scenario.participantCount,
    ),
    allowAbstention: scenario.allowAbstention ?? false,
    scoreDomainMin: scenario.allowAbstention ? 0 : 1,
    scoreDomainMax: scenario.scoreDomainMax ?? 10,
    ballotFinality: 'first-valid',
    rosterHash,
    optionList: ['Option A'],
    epochDeadlines: ['2026-04-08T12:00:00Z'],
});

export const createRegistrationPayloads = async (
    participants: readonly ParticipantRuntime[],
    sessionId: string,
    manifestHash: string,
    rosterHash: string,
): Promise<readonly SignedPayload<RegistrationPayload>[]> =>
    Promise.all(
        participants.map((participant) =>
            signPayload(participant.auth.privateKey, {
                sessionId,
                manifestHash,
                phase: 0,
                participantIndex: participant.index,
                messageType: 'registration',
                rosterHash,
                authPublicKey: participant.authPublicKeyHex,
                transportPublicKey: participant.transportPublicKeyHex,
            }),
        ),
    );

export const createAcceptancePayloads = async (
    participants: readonly ParticipantRuntime[],
    sessionId: string,
    manifestHash: string,
    rosterHash: string,
): Promise<readonly SignedPayload<ManifestAcceptancePayload>[]> =>
    Promise.all(
        participants.map((participant) =>
            signPayload(participant.auth.privateKey, {
                sessionId,
                manifestHash,
                phase: 0,
                participantIndex: participant.index,
                messageType: 'manifest-acceptance',
                rosterHash,
                assignedParticipantIndex: participant.index,
            }),
        ),
    );
