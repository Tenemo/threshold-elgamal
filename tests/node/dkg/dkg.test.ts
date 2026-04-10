import { p256 } from '@noble/curves/nist.js';
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
    processGjkrPayload,
    reconstructSecretFromShares,
    replayGjkrTranscript,
} from '#dkg';
import {
    canonicalUnsignedPayloadBytes,
    type ComplaintResolutionPayload,
    type KeyDerivationConfirmation,
    type ProtocolPayload,
    type RegistrationPayload,
    type SignedPayload,
} from '#protocol';
import { bytesToHex } from '#serialize';

const AUTH_PUBLIC_KEY_SPKI_PREFIX =
    '3059301306072a8648ce3d020106082a8648ce3d030107034200';

type ReducerSigner = {
    readonly participantIndex: number;
    readonly secretKey: Uint8Array;
    readonly authPublicKey: RegistrationPayload['authPublicKey'];
    readonly transportPublicKey: RegistrationPayload['transportPublicKey'];
};

const reducerSignerCache = new Map<number, ReducerSigner>();

const reducerSigner = (participantIndex: number): ReducerSigner => {
    const cached = reducerSignerCache.get(participantIndex);
    if (cached !== undefined) {
        return cached;
    }

    const secretKey = new Uint8Array(32);
    secretKey[31] = participantIndex;

    const signer: ReducerSigner = {
        participantIndex,
        secretKey,
        authPublicKey: `${AUTH_PUBLIC_KEY_SPKI_PREFIX}${bytesToHex(
            p256.getPublicKey(secretKey, false),
        )}` as RegistrationPayload['authPublicKey'],
        transportPublicKey: bytesToHex(
            Uint8Array.from([participantIndex, participantIndex]),
        ) as RegistrationPayload['transportPublicKey'],
    };

    reducerSignerCache.set(participantIndex, signer);

    return signer;
};

const signed = <TPayload extends ProtocolPayload>(
    payload: TPayload,
): SignedPayload<TPayload> => ({
    payload,
    signature: bytesToHex(
        p256.sign(
            canonicalUnsignedPayloadBytes(payload),
            reducerSigner(payload.participantIndex).secretKey,
        ),
    ),
});

const registrationPayloads = (
    participantCount: number,
    sessionId: string,
    manifestHash: string,
    rosterHash: string,
): readonly SignedPayload<RegistrationPayload>[] =>
    Array.from({ length: participantCount }, (_value, index) => {
        const participantIndex = index + 1;
        const signer = reducerSigner(participantIndex);

        return signed({
            sessionId,
            manifestHash,
            phase: 0,
            participantIndex,
            messageType: 'registration',
            rosterHash,
            authPublicKey: signer.authPublicKey,
            transportPublicKey: signer.transportPublicKey,
        });
    });

const manifestAcceptancePayloads = (
    participantCount: number,
    sessionId: string,
    manifestHash: string,
    rosterHash: string,
): readonly SignedPayload[] =>
    Array.from({ length: participantCount }, (_value, index) => {
        const participantIndex = index + 1;

        return signed({
            sessionId,
            manifestHash,
            phase: 0,
            participantIndex,
            messageType: 'manifest-acceptance',
            rosterHash,
            assignedParticipantIndex: participantIndex,
        });
    });

const pedersenCommitmentPayloads = (
    participantCount: number,
    sessionId: string,
    manifestHash: string,
): readonly SignedPayload[] =>
    Array.from({ length: participantCount }, (_value, index) => {
        const participantIndex = index + 1;

        return signed({
            sessionId,
            manifestHash,
            phase: 1,
            participantIndex,
            messageType: 'pedersen-commitment',
            commitments: [`pc-${participantIndex}`],
        });
    });

const feldmanCommitmentPayloads = (
    participantCount: number,
    sessionId: string,
    manifestHash: string,
): readonly SignedPayload[] =>
    Array.from({ length: participantCount }, (_value, index) => {
        const participantIndex = index + 1;

        return signed({
            sessionId,
            manifestHash,
            phase: 3,
            participantIndex,
            messageType: 'feldman-commitment',
            commitments: [`fc-${participantIndex}`],
            proofs: [],
        });
    });

const keyDerivationPayloads = (
    participantIndices: readonly number[],
    sessionId: string,
    manifestHash: string,
): readonly SignedPayload[] =>
    participantIndices.map((participantIndex) =>
        signed({
            sessionId,
            manifestHash,
            phase: 4,
            participantIndex,
            messageType: 'key-derivation-confirmation',
            qualHash: 'qual',
            publicKey: 'pk' as KeyDerivationConfirmation['publicKey'],
        }),
    );

const complaintResolutionPayload = (
    sessionId: string,
    manifestHash: string,
    participantIndex: number,
    dealerIndex: number,
    complainantIndex: number,
    envelopeId: string,
): SignedPayload =>
    signed({
        sessionId,
        manifestHash,
        phase: 2,
        participantIndex,
        messageType: 'complaint-resolution',
        dealerIndex,
        complainantIndex,
        envelopeId,
        suite: 'P-256',
        revealedEphemeralPrivateKey:
            'ephemeral-private-key' as ComplaintResolutionPayload['revealedEphemeralPrivateKey'],
    });

const config = (
    suffix: string,
    participantCount: number,
    threshold = majorityThreshold(participantCount),
): Readonly<{
    readonly sessionId: string;
    readonly manifestHash: string;
    readonly participantCount: number;
    readonly threshold: number;
}> =>
    ({
        sessionId: `session-${suffix}`,
        manifestHash: `manifest-${suffix}`,
        participantCount,
        threshold,
    }) as const;

const thresholdVectorGroup = thresholdVector.group as 'ristretto255';

describe('dkg state machines', () => {
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
        const state = createGjkrState(config('gate', 3));
        const registeredState = processGjkrPayload(
            state,
            registrationPayloads(
                3,
                'session-gate',
                'manifest-gate',
                'roster-gate',
            )[0],
        ).newState;

        const transition = processGjkrPayload(
            registeredState,
            signed({
                sessionId: 'session-gate',
                manifestHash: 'manifest-gate',
                phase: 1,
                participantIndex: 1,
                messageType: 'pedersen-commitment',
                commitments: ['pc-1'],
            }),
        );

        expect(transition.errors[0]?.code).toBe('manifest-acceptance-required');
        expect(transition.newState).toBe(registeredState);
    });

    it('replays GJKR transcripts deterministically', () => {
        const gjkrConfig = config('deterministic', 3);
        const transcript = [
            ...registrationPayloads(
                gjkrConfig.participantCount,
                gjkrConfig.sessionId,
                gjkrConfig.manifestHash,
                'roster-deterministic',
            ),
            ...manifestAcceptancePayloads(
                gjkrConfig.participantCount,
                gjkrConfig.sessionId,
                gjkrConfig.manifestHash,
                'roster-deterministic',
            ),
            ...pedersenCommitmentPayloads(
                gjkrConfig.participantCount,
                gjkrConfig.sessionId,
                gjkrConfig.manifestHash,
            ),
            ...feldmanCommitmentPayloads(
                gjkrConfig.participantCount,
                gjkrConfig.sessionId,
                gjkrConfig.manifestHash,
            ),
            ...keyDerivationPayloads(
                [1, 2, 3],
                gjkrConfig.sessionId,
                gjkrConfig.manifestHash,
            ),
        ] as const;

        const finalState = replayGjkrTranscript(gjkrConfig, transcript);
        const secondReplay = replayGjkrTranscript(gjkrConfig, transcript);

        expect(finalState.phase).toBe('completed');
        expect(finalState.qual).toEqual([1, 2, 3]);
        expect(secondReplay).toEqual(finalState);
    });

    it('replays GJKR transcripts, keeps false complainants in QUAL, and aborts when QUAL drops below k', () => {
        const gjkrConfig = config('qual', 5);
        const transcript = [
            ...registrationPayloads(
                gjkrConfig.participantCount,
                gjkrConfig.sessionId,
                gjkrConfig.manifestHash,
                'roster-qual',
            ),
            ...manifestAcceptancePayloads(
                gjkrConfig.participantCount,
                gjkrConfig.sessionId,
                gjkrConfig.manifestHash,
                'roster-qual',
            ),
            ...pedersenCommitmentPayloads(
                gjkrConfig.participantCount,
                gjkrConfig.sessionId,
                gjkrConfig.manifestHash,
            ),
            signed({
                sessionId: gjkrConfig.sessionId,
                manifestHash: gjkrConfig.manifestHash,
                phase: 2,
                participantIndex: 2,
                messageType: 'complaint',
                dealerIndex: 5,
                envelopeId: 'env-5',
                reason: 'pedersen-failure',
            }),
            ...keyDerivationPayloads(
                [1, 2, 3, 4],
                gjkrConfig.sessionId,
                gjkrConfig.manifestHash,
            ),
        ] as const;

        const finalState = replayGjkrTranscript(gjkrConfig, transcript);

        expect(finalState.phase).toBe('completed');
        expect(finalState.qual).toEqual([1, 2, 3, 4]);
        expect(finalState.qual).toContain(2);
        expect(finalState.qual).not.toContain(5);

        const abortedState = replayGjkrTranscript(gjkrConfig, [
            ...transcript.slice(0, -4),
            signed({
                sessionId: gjkrConfig.sessionId,
                manifestHash: gjkrConfig.manifestHash,
                phase: 2,
                participantIndex: 3,
                messageType: 'complaint',
                dealerIndex: 3,
                envelopeId: 'env-3',
                reason: 'pedersen-failure',
            }),
            signed({
                sessionId: gjkrConfig.sessionId,
                manifestHash: gjkrConfig.manifestHash,
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
        const gjkrConfig = config('resume', 3);
        const transcript = [
            ...registrationPayloads(
                gjkrConfig.participantCount,
                gjkrConfig.sessionId,
                gjkrConfig.manifestHash,
                'roster-resume',
            ),
            ...manifestAcceptancePayloads(
                gjkrConfig.participantCount,
                gjkrConfig.sessionId,
                gjkrConfig.manifestHash,
                'roster-resume',
            ),
            ...pedersenCommitmentPayloads(
                gjkrConfig.participantCount,
                gjkrConfig.sessionId,
                gjkrConfig.manifestHash,
            ),
            signed({
                sessionId: gjkrConfig.sessionId,
                manifestHash: gjkrConfig.manifestHash,
                phase: 2,
                participantIndex: 2,
                messageType: 'complaint',
                dealerIndex: 1,
                envelopeId: 'env-1-2',
                reason: 'aes-gcm-failure',
            }),
            complaintResolutionPayload(
                gjkrConfig.sessionId,
                gjkrConfig.manifestHash,
                1,
                1,
                2,
                'env-1-2',
            ),
            ...keyDerivationPayloads(
                [1, 2, 3],
                gjkrConfig.sessionId,
                gjkrConfig.manifestHash,
            ),
        ] as const;

        const prefixState = replayGjkrTranscript(
            gjkrConfig,
            transcript.slice(0, 8),
        );
        let resumedState = prefixState;

        for (const payload of transcript.slice(8)) {
            resumedState = processGjkrPayload(resumedState, payload).newState;
        }

        const directReplay = replayGjkrTranscript(gjkrConfig, transcript);

        expect(prefixState.phase).toBe(1);
        expect(resumedState).toEqual(directReplay);
        expect(directReplay.phase).toBe('completed');
        expect(directReplay.qual).toEqual([1, 2, 3]);
    });

    it('ignores malformed complaint resolutions when deriving QUAL in reducers', () => {
        const gjkrConfig = config('complaints', 3);
        const registrations = registrationPayloads(
            gjkrConfig.participantCount,
            gjkrConfig.sessionId,
            gjkrConfig.manifestHash,
            'roster-complaints',
        );
        const acceptances = manifestAcceptancePayloads(
            gjkrConfig.participantCount,
            gjkrConfig.sessionId,
            gjkrConfig.manifestHash,
            'roster-complaints',
        );
        const pedersenCommitments = pedersenCommitmentPayloads(
            gjkrConfig.participantCount,
            gjkrConfig.sessionId,
            gjkrConfig.manifestHash,
        );
        const complaint = signed({
            sessionId: gjkrConfig.sessionId,
            manifestHash: gjkrConfig.manifestHash,
            phase: 2,
            participantIndex: 2,
            messageType: 'complaint',
            dealerIndex: 1,
            envelopeId: 'env-1-2',
            reason: 'aes-gcm-failure',
        });
        const confirmations = keyDerivationPayloads(
            [2, 3],
            gjkrConfig.sessionId,
            gjkrConfig.manifestHash,
        );

        const foreignResolutionState = replayGjkrTranscript(gjkrConfig, [
            ...registrations,
            ...acceptances,
            ...pedersenCommitments,
            complaint,
            complaintResolutionPayload(
                gjkrConfig.sessionId,
                gjkrConfig.manifestHash,
                3,
                1,
                2,
                'env-1-2',
            ),
            ...confirmations,
        ]);

        const mismatchedResolutionState = replayGjkrTranscript(gjkrConfig, [
            ...registrations,
            ...acceptances,
            ...pedersenCommitments,
            complaint,
            complaintResolutionPayload(
                gjkrConfig.sessionId,
                gjkrConfig.manifestHash,
                1,
                1,
                3,
                'env-1-2',
            ),
            ...confirmations,
        ]);

        expect(foreignResolutionState.phase).toBe('completed');
        expect(foreignResolutionState.qual).toEqual([2, 3]);
        expect(mismatchedResolutionState.phase).toBe('completed');
        expect(mismatchedResolutionState.qual).toEqual([2, 3]);
    });

    it('ignores idempotent retransmissions without regressing the reducer phase', () => {
        const state = createGjkrState(config('retransmit', 3));
        const registeredState = registrationPayloads(
            3,
            'session-retransmit',
            'manifest-retransmit',
            'roster-retransmit',
        ).reduce(
            (currentState, payload) =>
                processGjkrPayload(currentState, payload).newState,
            state,
        );
        const acceptance = signed({
            sessionId: 'session-retransmit',
            manifestHash: 'manifest-retransmit',
            phase: 0,
            participantIndex: 1,
            messageType: 'manifest-acceptance',
            rosterHash: 'roster-retransmit',
            assignedParticipantIndex: 1,
        });
        const stateAfterAcceptance = processGjkrPayload(
            processGjkrPayload(
                processGjkrPayload(registeredState, acceptance).newState,
                signed({
                    ...acceptance.payload,
                    participantIndex: 2,
                    assignedParticipantIndex: 2,
                }),
            ).newState,
            signed({
                ...acceptance.payload,
                participantIndex: 3,
                assignedParticipantIndex: 3,
            }),
        ).newState;
        const stateAfterCommitment = processGjkrPayload(
            stateAfterAcceptance,
            signed({
                sessionId: 'session-retransmit',
                manifestHash: 'manifest-retransmit',
                phase: 1,
                participantIndex: 1,
                messageType: 'pedersen-commitment',
                commitments: ['pc-1'],
            }),
        ).newState;
        const retransmitted = processGjkrPayload(
            stateAfterCommitment,
            acceptance,
        );

        expect(stateAfterCommitment.phase).toBe(1);
        expect(retransmitted.errors).toEqual([]);
        expect(retransmitted.newState).toBe(stateAfterCommitment);
        expect(retransmitted.newState.phase).toBe(1);
    });

    it('rejects unregistered and forged reducer payloads before they affect state', () => {
        const state = createGjkrState(config('auth', 3));
        const unregisteredAcceptance = processGjkrPayload(
            state,
            signed({
                sessionId: 'session-auth',
                manifestHash: 'manifest-auth',
                phase: 0,
                participantIndex: 1,
                messageType: 'manifest-acceptance',
                rosterHash: 'roster-auth',
                assignedParticipantIndex: 1,
            }),
        );
        const registeredState = registrationPayloads(
            3,
            'session-auth',
            'manifest-auth',
            'roster-auth',
        ).reduce(
            (currentState, payload) =>
                processGjkrPayload(currentState, payload).newState,
            state,
        );
        const forgedAcceptance = processGjkrPayload(registeredState, {
            payload: {
                sessionId: 'session-auth',
                manifestHash: 'manifest-auth',
                phase: 0,
                participantIndex: 1,
                messageType: 'manifest-acceptance',
                rosterHash: 'roster-auth',
                assignedParticipantIndex: 1,
            },
            signature: '00'.repeat(64),
        });

        expect(unregisteredAcceptance.errors[0]?.code).toBe(
            'registration-required',
        );
        expect(unregisteredAcceptance.newState).toBe(state);
        expect(forgedAcceptance.errors[0]?.code).toBe('signature-invalid');
        expect(forgedAcceptance.newState).toBe(registeredState);
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
        const state = createGjkrState(config('equivocation', 3));
        const registeredState = processGjkrPayload(
            state,
            registrationPayloads(
                3,
                'session-equivocation',
                'manifest-equivocation',
                'roster-equivocation',
            )[0],
        ).newState;
        const acceptedState = processGjkrPayload(
            registeredState,
            signed({
                sessionId: 'session-equivocation',
                manifestHash: 'manifest-equivocation',
                phase: 0,
                participantIndex: 1,
                messageType: 'manifest-acceptance',
                rosterHash: 'roster-equivocation',
                assignedParticipantIndex: 1,
            }),
        ).newState;
        const equivocation = processGjkrPayload(
            acceptedState,
            signed({
                sessionId: 'session-equivocation',
                manifestHash: 'manifest-equivocation',
                phase: 0,
                participantIndex: 1,
                messageType: 'manifest-acceptance',
                rosterHash: 'other-roster',
                assignedParticipantIndex: 1,
            }),
        );

        expect(equivocation.errors[0]?.code).toBe('equivocation');
        expect(equivocation.newState.phase).toBe('aborted');
    });
});
