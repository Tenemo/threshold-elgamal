import { describe, expect, it } from 'vitest';

import thresholdVector from '../../../test-vectors/threshold.json';

import { getGroup } from '#core';
import {
    createGjkrState,
    createJointFeldmanState,
    processGjkrPayload,
    processJointFeldmanPayload,
    reconstructSecretFromShares,
    replayGjkrTranscript,
    replayJointFeldmanTranscript,
    type DKGConfig,
} from '#dkg';
import type { ProtocolPayload, SignedPayload } from '#protocol';

const signed = <TPayload extends ProtocolPayload>(
    payload: TPayload,
): SignedPayload<TPayload> => ({
    payload,
    signature: `${payload.messageType}-${payload.participantIndex}`,
});

describe('DKG state machines', () => {
    it('reconstructs the secret term from revealed shares', () => {
        const group = getGroup(thresholdVector.group as 'ffdhe3072');
        const subsetShares = thresholdVector.shares
            .filter((share) =>
                thresholdVector.subsetIndices.includes(share.index),
            )
            .map((share) => ({
                index: share.index,
                value: BigInt(share.value),
            }));

        expect(reconstructSecretFromShares(subsetShares, group.q)).toBe(
            BigInt(thresholdVector.polynomial[0]),
        );
    });

    it('gates phase 1 on manifest acceptance', () => {
        const state = createGjkrState({
            protocol: 'gjkr',
            sessionId: 'session-1',
            manifestHash: 'manifest-1',
            group: 'ffdhe2048',
            participantCount: 3,
            threshold: 2,
        });
        const transition = processGjkrPayload(
            state,
            signed({
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 1,
                participantIndex: 1,
                messageType: 'pedersen-commitment',
                commitments: ['a'],
            }),
        );

        expect(transition.errors[0]?.code).toBe('manifest-acceptance-required');
        expect(transition.newState).toBe(state);
    });

    it('replays Joint-Feldman transcripts deterministically', () => {
        const config: DKGConfig = {
            protocol: 'joint-feldman',
            sessionId: 'session-1',
            manifestHash: 'manifest-1',
            group: 'ffdhe2048',
            participantCount: 3,
            threshold: 2,
        };
        const transcript = [
            signed({
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 0,
                participantIndex: 1,
                messageType: 'manifest-acceptance',
                rosterHash: 'roster-1',
                assignedParticipantIndex: 1,
            }),
            signed({
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 0,
                participantIndex: 2,
                messageType: 'manifest-acceptance',
                rosterHash: 'roster-1',
                assignedParticipantIndex: 2,
            }),
            signed({
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 0,
                participantIndex: 3,
                messageType: 'manifest-acceptance',
                rosterHash: 'roster-1',
                assignedParticipantIndex: 3,
            }),
            signed({
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 1,
                participantIndex: 1,
                messageType: 'feldman-commitment',
                commitments: ['a'],
                proofs: [],
            }),
            signed({
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 1,
                participantIndex: 2,
                messageType: 'feldman-commitment',
                commitments: ['b'],
                proofs: [],
            }),
            signed({
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 1,
                participantIndex: 3,
                messageType: 'feldman-commitment',
                commitments: ['c'],
                proofs: [],
            }),
            signed({
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 3,
                participantIndex: 1,
                messageType: 'key-derivation-confirmation',
                qualHash: 'qual',
                publicKey: 'pk',
            }),
            signed({
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 3,
                participantIndex: 2,
                messageType: 'key-derivation-confirmation',
                qualHash: 'qual',
                publicKey: 'pk',
            }),
            signed({
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 3,
                participantIndex: 3,
                messageType: 'key-derivation-confirmation',
                qualHash: 'qual',
                publicKey: 'pk',
            }),
        ] as const;

        const finalState = replayJointFeldmanTranscript(config, transcript);
        const secondReplay = replayJointFeldmanTranscript(config, transcript);

        expect(finalState.phase).toBe('completed');
        expect(finalState.qual).toEqual([1, 2, 3]);
        expect(secondReplay).toEqual(finalState);
    });

    it('replays GJKR transcripts, keeps false complainants in QUAL, and aborts when QUAL drops below k', () => {
        const config: DKGConfig = {
            protocol: 'gjkr',
            sessionId: 'session-2',
            manifestHash: 'manifest-2',
            group: 'ffdhe2048',
            participantCount: 5,
            threshold: 3,
        };
        const transcript = [
            ...[1, 2, 3, 4, 5].map((participantIndex) =>
                signed({
                    sessionId: 'session-2',
                    manifestHash: 'manifest-2',
                    phase: 0,
                    participantIndex,
                    messageType: 'manifest-acceptance',
                    rosterHash: 'roster-2',
                    assignedParticipantIndex: participantIndex,
                }),
            ),
            ...[1, 2, 3, 4, 5].map((participantIndex) =>
                signed({
                    sessionId: 'session-2',
                    manifestHash: 'manifest-2',
                    phase: 1,
                    participantIndex,
                    messageType: 'pedersen-commitment',
                    commitments: [`c-${participantIndex}`],
                }),
            ),
            signed({
                sessionId: 'session-2',
                manifestHash: 'manifest-2',
                phase: 2,
                participantIndex: 2,
                messageType: 'complaint',
                dealerIndex: 5,
                envelopeId: 'env-5',
                reason: 'pedersen-failure',
            }),
            ...[1, 2, 3, 4].map((participantIndex) =>
                signed({
                    sessionId: 'session-2',
                    manifestHash: 'manifest-2',
                    phase: 4,
                    participantIndex,
                    messageType: 'key-derivation-confirmation',
                    qualHash: 'qual',
                    publicKey: 'pk',
                }),
            ),
        ];

        const finalState = replayGjkrTranscript(config, transcript);

        expect(finalState.phase).toBe('completed');
        expect(finalState.qual).toEqual([1, 2, 3, 4]);
        expect(finalState.qual).toContain(2);
        expect(finalState.qual).not.toContain(5);

        const abortConfig: DKGConfig = {
            ...config,
            threshold: 5,
        };
        const abortedState = replayGjkrTranscript(abortConfig, transcript);

        expect(abortedState.phase).toBe('aborted');
        expect(abortedState.abortReason).toBe('qual-too-small');
    });

    it('rejects equivocated payloads for the same canonical slot', () => {
        const state = createJointFeldmanState({
            protocol: 'joint-feldman',
            sessionId: 'session-3',
            manifestHash: 'manifest-3',
            group: 'ffdhe2048',
            participantCount: 2,
            threshold: 2,
        });
        const accepted = processJointFeldmanPayload(
            state,
            signed({
                sessionId: 'session-3',
                manifestHash: 'manifest-3',
                phase: 0,
                participantIndex: 1,
                messageType: 'manifest-acceptance',
                rosterHash: 'roster-3',
                assignedParticipantIndex: 1,
            }),
        ).newState;
        const equivocation = processJointFeldmanPayload(accepted, {
            payload: {
                sessionId: 'session-3',
                manifestHash: 'manifest-3',
                phase: 0,
                participantIndex: 1,
                messageType: 'manifest-acceptance',
                rosterHash: 'other-roster',
                assignedParticipantIndex: 1,
            },
            signature: 'different-signature',
        });

        expect(equivocation.errors[0]?.code).toBe('equivocation');
        expect(equivocation.newState.phase).toBe('aborted');
    });
});
