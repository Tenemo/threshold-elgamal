import { signPayload } from './common.js';
import type { ParticipantRuntime, VotingFlowScenario } from './types.js';

import { majorityThreshold, type CryptoGroup } from '#core';
import {
    defaultMinimumPublishedVoterCount,
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
): ElectionManifest => {
    const threshold =
        scenario.threshold ?? majorityThreshold(scenario.participantCount);
    const optionCount = scenario.votesByOption?.length ?? 1;
    const optionList =
        scenario.optionList ??
        Array.from({ length: optionCount }, (_value, index) => {
            const suffix = String.fromCharCode('A'.charCodeAt(0) + index);
            return `Option ${suffix}`;
        });

    return {
        protocolVersion: 'v1',
        suiteId: group.name,
        reconstructionThreshold: threshold,
        participantCount: scenario.participantCount,
        minimumPublishedVoterCount: defaultMinimumPublishedVoterCount(
            threshold,
            scenario.participantCount,
        ),
        ballotCompletenessPolicy: 'ALL_OPTIONS_REQUIRED',
        ballotFinality: 'first-valid',
        scoreDomain: '1..10',
        rosterHash,
        optionList,
        epochDeadlines: ['2026-04-08T12:00:00Z'],
    };
};

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
            } satisfies RegistrationPayload),
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
