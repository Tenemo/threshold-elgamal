import { describe, expect, it } from 'vitest';

import thresholdVector from '../../../test-vectors/threshold.json';

import {
    IndexOutOfRangeError,
    InvalidShareError,
    getGroup,
    majorityThreshold,
} from '#core';
import {
    collectCheckpointVariants,
    createGjkrState,
    createJointFeldmanState,
    processGjkrPayload,
    processJointFeldmanPayload,
    reconstructSecretFromShares,
    replayGjkrTranscript,
    replayJointFeldmanTranscript,
} from '#dkg';
import type {
    ComplaintResolutionPayload,
    KeyDerivationConfirmation,
    ProtocolPayload,
    SignedPayload,
} from '#protocol';

const signed = <TPayload extends ProtocolPayload>(
    payload: TPayload,
): SignedPayload<TPayload> => ({
    payload,
    signature: `${payload.messageType}-${payload.participantIndex}`,
});

const thresholdVectorGroup = thresholdVector.group as 'ristretto255';

describe('DKG state machines', () => {
    it('reconstructs the secret term from revealed shares', () => {
        const group = getGroup(thresholdVectorGroup);
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

    it('rejects malformed share indices during reconstruction', () => {
        const group = getGroup(thresholdVectorGroup);

        expect(() =>
            reconstructSecretFromShares(
                [
                    { index: 1, value: 10n },
                    { index: 1, value: 12n },
                ],
                group.q,
            ),
        ).toThrow(InvalidShareError);
        expect(() =>
            reconstructSecretFromShares(
                [
                    { index: 0, value: 10n },
                    { index: 2, value: 12n },
                ],
                group.q,
            ),
        ).toThrow(IndexOutOfRangeError);
    });

    it('gates phase 1 on manifest acceptance', () => {
        const state = createGjkrState({
            protocol: 'gjkr',
            sessionId: 'session-1',
            manifestHash: 'manifest-1',
            group: 'ristretto255',
            participantCount: 3,
            threshold: majorityThreshold(3),
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
        const config = {
            protocol: 'joint-feldman',
            sessionId: 'session-1',
            manifestHash: 'manifest-1',
            group: 'ristretto255',
            participantCount: 3,
            threshold: majorityThreshold(3),
        } as const;
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
                publicKey: 'pk' as KeyDerivationConfirmation['publicKey'],
            }),
            signed({
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 3,
                participantIndex: 2,
                messageType: 'key-derivation-confirmation',
                qualHash: 'qual',
                publicKey: 'pk' as KeyDerivationConfirmation['publicKey'],
            }),
            signed({
                sessionId: 'session-1',
                manifestHash: 'manifest-1',
                phase: 3,
                participantIndex: 3,
                messageType: 'key-derivation-confirmation',
                qualHash: 'qual',
                publicKey: 'pk' as KeyDerivationConfirmation['publicKey'],
            }),
        ] as const;

        const finalState = replayJointFeldmanTranscript(config, transcript);
        const secondReplay = replayJointFeldmanTranscript(config, transcript);

        expect(finalState.phase).toBe('completed');
        expect(finalState.qual).toEqual([1, 2, 3]);
        expect(secondReplay).toEqual(finalState);
    });

    it('keeps shared QUAL and terminal-state behavior aligned across both majority reducers', () => {
        const baseConfig = {
            sessionId: 'session-shared',
            manifestHash: 'manifest-shared',
            group: 'ristretto255',
            participantCount: 3,
            threshold: majorityThreshold(3),
        } as const;
        const jointTranscript = [
            ...[1, 2, 3].map((participantIndex) =>
                signed({
                    sessionId: baseConfig.sessionId,
                    manifestHash: baseConfig.manifestHash,
                    phase: 0,
                    participantIndex,
                    messageType: 'manifest-acceptance',
                    rosterHash: 'roster-shared',
                    assignedParticipantIndex: participantIndex,
                }),
            ),
            ...[1, 2, 3].map((participantIndex) =>
                signed({
                    sessionId: baseConfig.sessionId,
                    manifestHash: baseConfig.manifestHash,
                    phase: 1,
                    participantIndex,
                    messageType: 'feldman-commitment',
                    commitments: [`c-${participantIndex}`],
                    proofs: [],
                }),
            ),
            signed({
                sessionId: baseConfig.sessionId,
                manifestHash: baseConfig.manifestHash,
                phase: 2,
                participantIndex: 2,
                messageType: 'complaint',
                dealerIndex: 1,
                envelopeId: 'env-1-2',
                reason: 'aes-gcm-failure',
            }),
            signed({
                sessionId: baseConfig.sessionId,
                manifestHash: baseConfig.manifestHash,
                phase: 2,
                participantIndex: 1,
                messageType: 'complaint-resolution',
                dealerIndex: 1,
                complainantIndex: 2,
                envelopeId: 'env-1-2',
                suite: 'P-256',
                revealedEphemeralPrivateKey:
                    'ephemeral-private-key' as ComplaintResolutionPayload['revealedEphemeralPrivateKey'],
            }),
            ...[1, 2, 3].map((participantIndex) =>
                signed({
                    sessionId: baseConfig.sessionId,
                    manifestHash: baseConfig.manifestHash,
                    phase: 3,
                    participantIndex,
                    messageType: 'key-derivation-confirmation',
                    qualHash: 'qual',
                    publicKey: 'pk' as KeyDerivationConfirmation['publicKey'],
                }),
            ),
        ] as const;
        const gjkrTranscript = [
            ...jointTranscript.slice(0, 3),
            ...[1, 2, 3].map((participantIndex) =>
                signed({
                    sessionId: baseConfig.sessionId,
                    manifestHash: baseConfig.manifestHash,
                    phase: 1,
                    participantIndex,
                    messageType: 'pedersen-commitment',
                    commitments: [`pc-${participantIndex}`],
                }),
            ),
            ...jointTranscript.slice(6, 8),
            ...jointTranscript.slice(8).map((entry) =>
                entry.payload.messageType === 'key-derivation-confirmation'
                    ? signed({
                          ...entry.payload,
                          phase: 4,
                      })
                    : entry,
            ),
        ] as const;

        const gjkrState = replayGjkrTranscript(
            {
                ...baseConfig,
                protocol: 'gjkr',
            },
            gjkrTranscript,
        );
        const jointState = replayJointFeldmanTranscript(
            {
                ...baseConfig,
                protocol: 'joint-feldman',
            },
            jointTranscript,
        );

        expect(gjkrState.phase).toBe('completed');
        expect(jointState.phase).toBe('completed');
        expect(gjkrState.qual).toEqual([1, 2, 3]);
        expect(jointState.qual).toEqual(gjkrState.qual);
        expect(jointState.manifestAccepted).toEqual(gjkrState.manifestAccepted);
    });

    it('replays GJKR transcripts, keeps false complainants in QUAL, and aborts when QUAL drops below k', () => {
        const config = {
            protocol: 'gjkr',
            sessionId: 'session-2',
            manifestHash: 'manifest-2',
            group: 'ristretto255',
            participantCount: 5,
            threshold: majorityThreshold(5),
        } as const;
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
                    publicKey: 'pk' as KeyDerivationConfirmation['publicKey'],
                }),
            ),
        ];

        const finalState = replayGjkrTranscript(config, transcript);

        expect(finalState.phase).toBe('completed');
        expect(finalState.qual).toEqual([1, 2, 3, 4]);
        expect(finalState.qual).toContain(2);
        expect(finalState.qual).not.toContain(5);

        const abortedState = replayGjkrTranscript(config, [
            ...transcript.slice(0, -4),
            signed({
                sessionId: 'session-2',
                manifestHash: 'manifest-2',
                phase: 2,
                participantIndex: 3,
                messageType: 'complaint',
                dealerIndex: 3,
                envelopeId: 'env-3',
                reason: 'pedersen-failure',
            }),
            signed({
                sessionId: 'session-2',
                manifestHash: 'manifest-2',
                phase: 2,
                participantIndex: 4,
                messageType: 'complaint',
                dealerIndex: 4,
                envelopeId: 'env-4',
                reason: 'pedersen-failure',
            }),
            ...transcript.slice(-4),
        ]);

        expect(abortedState.phase).toBe('aborted');
        expect(abortedState.abortReason).toBe('qual-too-small');
    });

    it('resumes GJKR processing from a transcript prefix without changing the final state', () => {
        const config = {
            protocol: 'gjkr',
            sessionId: 'session-4',
            manifestHash: 'manifest-4',
            group: 'ristretto255',
            participantCount: 3,
            threshold: majorityThreshold(3),
        } as const;
        const transcript = [
            ...[1, 2, 3].map((participantIndex) =>
                signed({
                    sessionId: 'session-4',
                    manifestHash: 'manifest-4',
                    phase: 0,
                    participantIndex,
                    messageType: 'manifest-acceptance',
                    rosterHash: 'roster-4',
                    assignedParticipantIndex: participantIndex,
                }),
            ),
            ...[1, 2, 3].map((participantIndex) =>
                signed({
                    sessionId: 'session-4',
                    manifestHash: 'manifest-4',
                    phase: 1,
                    participantIndex,
                    messageType: 'pedersen-commitment',
                    commitments: [`c-${participantIndex}`],
                }),
            ),
            signed({
                sessionId: 'session-4',
                manifestHash: 'manifest-4',
                phase: 2,
                participantIndex: 2,
                messageType: 'complaint',
                dealerIndex: 1,
                envelopeId: 'env-1-2',
                reason: 'aes-gcm-failure',
            }),
            signed({
                sessionId: 'session-4',
                manifestHash: 'manifest-4',
                phase: 2,
                participantIndex: 1,
                messageType: 'complaint-resolution',
                dealerIndex: 1,
                complainantIndex: 2,
                envelopeId: 'env-1-2',
                suite: 'P-256',
                revealedEphemeralPrivateKey:
                    'ephemeral-private-key' as ComplaintResolutionPayload['revealedEphemeralPrivateKey'],
            }),
            ...[1, 2, 3].map((participantIndex) =>
                signed({
                    sessionId: 'session-4',
                    manifestHash: 'manifest-4',
                    phase: 4,
                    participantIndex,
                    messageType: 'key-derivation-confirmation',
                    qualHash: 'qual',
                    publicKey: 'pk' as KeyDerivationConfirmation['publicKey'],
                }),
            ),
        ] as const;

        const prefixState = replayGjkrTranscript(
            config,
            transcript.slice(0, 5),
        );
        let resumedState = prefixState;
        for (const payload of transcript.slice(5)) {
            resumedState = processGjkrPayload(resumedState, payload).newState;
        }

        const directReplay = replayGjkrTranscript(config, transcript);

        expect(prefixState.phase).toBe(1);
        expect(resumedState).toEqual(directReplay);
        expect(directReplay.phase).toBe('completed');
        expect(directReplay.qual).toEqual([1, 2, 3]);
    });

    it('ignores malformed complaint resolutions when deriving QUAL in reducers', () => {
        const config = {
            protocol: 'gjkr',
            sessionId: 'session-4b',
            manifestHash: 'manifest-4b',
            group: 'ristretto255',
            participantCount: 3,
            threshold: majorityThreshold(3),
        } as const;
        const acceptancePayloads = [1, 2, 3].map((participantIndex) =>
            signed({
                sessionId: 'session-4b',
                manifestHash: 'manifest-4b',
                phase: 0,
                participantIndex,
                messageType: 'manifest-acceptance',
                rosterHash: 'roster-4b',
                assignedParticipantIndex: participantIndex,
            }),
        );
        const pedersenPayloads = [1, 2, 3].map((participantIndex) =>
            signed({
                sessionId: 'session-4b',
                manifestHash: 'manifest-4b',
                phase: 1,
                participantIndex,
                messageType: 'pedersen-commitment',
                commitments: [`c-${participantIndex}`],
            }),
        );
        const complaintPayload = signed({
            sessionId: 'session-4b',
            manifestHash: 'manifest-4b',
            phase: 2,
            participantIndex: 2,
            messageType: 'complaint',
            dealerIndex: 1,
            envelopeId: 'env-1-2',
            reason: 'aes-gcm-failure',
        });
        const confirmationPayloads = [2, 3].map((participantIndex) =>
            signed({
                sessionId: 'session-4b',
                manifestHash: 'manifest-4b',
                phase: 4,
                participantIndex,
                messageType: 'key-derivation-confirmation',
                qualHash: 'qual',
                publicKey: 'pk' as KeyDerivationConfirmation['publicKey'],
            }),
        );

        const foreignResolutionState = replayGjkrTranscript(config, [
            ...acceptancePayloads,
            ...pedersenPayloads,
            complaintPayload,
            signed({
                sessionId: 'session-4b',
                manifestHash: 'manifest-4b',
                phase: 2,
                participantIndex: 3,
                messageType: 'complaint-resolution',
                dealerIndex: 1,
                complainantIndex: 2,
                envelopeId: 'env-1-2',
                suite: 'P-256',
                revealedEphemeralPrivateKey:
                    'ephemeral-private-key' as ComplaintResolutionPayload['revealedEphemeralPrivateKey'],
            }),
            ...confirmationPayloads,
        ]);
        const mismatchedResolutionState = replayGjkrTranscript(config, [
            ...acceptancePayloads,
            ...pedersenPayloads,
            complaintPayload,
            signed({
                sessionId: 'session-4b',
                manifestHash: 'manifest-4b',
                phase: 2,
                participantIndex: 1,
                messageType: 'complaint-resolution',
                dealerIndex: 1,
                complainantIndex: 3,
                envelopeId: 'env-1-2',
                suite: 'P-256',
                revealedEphemeralPrivateKey:
                    'ephemeral-private-key' as ComplaintResolutionPayload['revealedEphemeralPrivateKey'],
            }),
            ...confirmationPayloads,
        ]);

        expect(foreignResolutionState.phase).toBe('completed');
        expect(foreignResolutionState.qual).toEqual([2, 3]);
        expect(mismatchedResolutionState.phase).toBe('completed');
        expect(mismatchedResolutionState.qual).toEqual([2, 3]);
    });

    it('ignores idempotent retransmissions without regressing the reducer phase', () => {
        const gjkrState = createGjkrState({
            protocol: 'gjkr',
            sessionId: 'session-5',
            manifestHash: 'manifest-5',
            group: 'ristretto255',
            participantCount: 3,
            threshold: majorityThreshold(3),
        });
        const gjkrAcceptance = signed({
            sessionId: 'session-5',
            manifestHash: 'manifest-5',
            phase: 0,
            participantIndex: 1,
            messageType: 'manifest-acceptance',
            rosterHash: 'roster-5',
            assignedParticipantIndex: 1,
        });
        const gjkrStateAfterAcceptance = processGjkrPayload(
            processGjkrPayload(
                processGjkrPayload(gjkrState, gjkrAcceptance).newState,
                signed({
                    ...gjkrAcceptance.payload,
                    participantIndex: 2,
                    assignedParticipantIndex: 2,
                }),
            ).newState,
            signed({
                ...gjkrAcceptance.payload,
                participantIndex: 3,
                assignedParticipantIndex: 3,
            }),
        ).newState;
        const gjkrStateAfterCommitment = processGjkrPayload(
            gjkrStateAfterAcceptance,
            signed({
                sessionId: 'session-5',
                manifestHash: 'manifest-5',
                phase: 1,
                participantIndex: 1,
                messageType: 'pedersen-commitment',
                commitments: ['c-1'],
            }),
        ).newState;
        const gjkrRetransmitted = processGjkrPayload(
            gjkrStateAfterCommitment,
            gjkrAcceptance,
        );

        expect(gjkrStateAfterCommitment.phase).toBe(1);
        expect(gjkrRetransmitted.errors).toEqual([]);
        expect(gjkrRetransmitted.newState).toBe(gjkrStateAfterCommitment);
        expect(gjkrRetransmitted.newState.phase).toBe(1);

        const jointState = createJointFeldmanState({
            protocol: 'joint-feldman',
            sessionId: 'session-6',
            manifestHash: 'manifest-6',
            group: 'ristretto255',
            participantCount: 3,
            threshold: majorityThreshold(3),
        });
        const jointAcceptance = signed({
            sessionId: 'session-6',
            manifestHash: 'manifest-6',
            phase: 0,
            participantIndex: 1,
            messageType: 'manifest-acceptance',
            rosterHash: 'roster-6',
            assignedParticipantIndex: 1,
        });
        const jointStateAfterAcceptance = processJointFeldmanPayload(
            processJointFeldmanPayload(
                processJointFeldmanPayload(jointState, jointAcceptance)
                    .newState,
                signed({
                    ...jointAcceptance.payload,
                    participantIndex: 2,
                    assignedParticipantIndex: 2,
                }),
            ).newState,
            signed({
                ...jointAcceptance.payload,
                participantIndex: 3,
                assignedParticipantIndex: 3,
            }),
        ).newState;
        const jointStateAfterCommitment = processJointFeldmanPayload(
            jointStateAfterAcceptance,
            signed({
                sessionId: 'session-6',
                manifestHash: 'manifest-6',
                phase: 1,
                participantIndex: 1,
                messageType: 'feldman-commitment',
                commitments: ['c-1'],
                proofs: [],
            }),
        ).newState;
        const jointRetransmitted = processJointFeldmanPayload(
            jointStateAfterCommitment,
            jointAcceptance,
        );

        expect(jointStateAfterCommitment.phase).toBe(1);
        expect(jointRetransmitted.errors).toEqual([]);
        expect(jointRetransmitted.newState).toBe(jointStateAfterCommitment);
        expect(jointRetransmitted.newState.phase).toBe(1);
    });

    it('groups matching phase checkpoints across multiple signers into one variant', () => {
        const transcript = [
            signed({
                sessionId: 'session-checkpoint',
                manifestHash: 'manifest-checkpoint',
                phase: 0,
                participantIndex: 1,
                messageType: 'phase-checkpoint',
                checkpointPhase: 0,
                checkpointTranscriptHash: 'hash-a',
                qualParticipantIndices: [1, 2, 3],
            }),
            signed({
                sessionId: 'session-checkpoint',
                manifestHash: 'manifest-checkpoint',
                phase: 0,
                participantIndex: 2,
                messageType: 'phase-checkpoint',
                checkpointPhase: 0,
                checkpointTranscriptHash: 'hash-a',
                qualParticipantIndices: [1, 2, 3],
            }),
            signed({
                sessionId: 'session-checkpoint',
                manifestHash: 'manifest-checkpoint',
                phase: 0,
                participantIndex: 3,
                messageType: 'phase-checkpoint',
                checkpointPhase: 0,
                checkpointTranscriptHash: 'hash-b',
                qualParticipantIndices: [1, 2],
            }),
        ] as const;

        const grouped = collectCheckpointVariants(transcript, 0);

        expect(grouped).toHaveLength(2);
        expect(grouped[0]?.signers).toEqual([1, 2]);
        expect(grouped[0]?.payload.checkpointTranscriptHash).toBe('hash-a');
        expect(grouped[1]?.signers).toEqual([3]);
        expect(grouped[1]?.payload.checkpointTranscriptHash).toBe('hash-b');
    });

    it('rejects equivocated payloads for the same canonical slot', () => {
        const state = createJointFeldmanState({
            protocol: 'joint-feldman',
            sessionId: 'session-3',
            manifestHash: 'manifest-3',
            group: 'ristretto255',
            participantCount: 3,
            threshold: majorityThreshold(3),
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
