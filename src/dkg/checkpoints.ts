import { InvalidPayloadError } from '../core/index.js';
import { hashProtocolPhaseSnapshot } from '../protocol/transcript.js';
import type {
    PhaseCheckpointPayload,
    SignedPayload,
} from '../protocol/types.js';

import {
    assertIndexSubset,
    assertUniqueSortedParticipantIndices,
    type ResolvePhaseCheckpointInput,
} from './verification.js';

/** Finalized threshold-supported checkpoint for one DKG phase. */
export type FinalizedPhaseCheckpoint = {
    readonly payload: PhaseCheckpointPayload;
    readonly signatures: readonly SignedPayload<PhaseCheckpointPayload>[];
    readonly signers: readonly number[];
};

const checkpointKey = (payload: PhaseCheckpointPayload): string =>
    JSON.stringify({
        sessionId: payload.sessionId,
        manifestHash: payload.manifestHash,
        phase: payload.phase,
        messageType: payload.messageType,
        checkpointPhase: payload.checkpointPhase,
        checkpointTranscriptHash: payload.checkpointTranscriptHash,
        qualifiedParticipantIndices: payload.qualifiedParticipantIndices,
    });

const compareNumbers = (left: number, right: number): number => left - right;
const sameParticipantIndexList = (
    left: readonly number[],
    right: readonly number[],
): boolean =>
    left.length === right.length &&
    left.every((participantIndex, index) => participantIndex === right[index]);

/** Returns `true` when the signed payload is a phase checkpoint. */
export const isPhaseCheckpointPayload = (
    payload: SignedPayload,
): payload is SignedPayload<PhaseCheckpointPayload> =>
    payload.payload.messageType === 'phase-checkpoint';

const requiredCheckpointPhases = (): readonly number[] => [0, 1, 2, 3];

const collectCheckpointVariants = (
    transcript: readonly SignedPayload[],
    checkpointPhase: number,
): readonly FinalizedPhaseCheckpoint[] => {
    const grouped = new Map<
        string,
        Map<number, SignedPayload<PhaseCheckpointPayload>>
    >();

    for (const signedPayload of transcript) {
        if (
            !isPhaseCheckpointPayload(signedPayload) ||
            signedPayload.payload.checkpointPhase !== checkpointPhase
        ) {
            continue;
        }

        const key = checkpointKey(signedPayload.payload);
        const existing =
            grouped.get(key) ??
            new Map<number, SignedPayload<PhaseCheckpointPayload>>();
        existing.set(signedPayload.payload.participantIndex, signedPayload);
        grouped.set(key, existing);
    }

    return [...grouped.values()].map((signatureMap) => {
        const signatures = [...signatureMap.values()];

        return {
            payload: signatures[0].payload,
            signatures,
            signers: signatures
                .map((entry) => entry.payload.participantIndex)
                .sort(compareNumbers),
        };
    });
};

/**
 * Rejects phase-checkpoint payloads outside the shipped GJKR checkpoint plan.
 */
export const assertSupportedCheckpointPayloads = (
    transcript: readonly SignedPayload[],
): void => {
    for (const signedPayload of transcript) {
        if (
            isPhaseCheckpointPayload(signedPayload) &&
            !requiredCheckpointPhases().includes(
                signedPayload.payload.checkpointPhase,
            )
        ) {
            throw new InvalidPayloadError(
                `Checkpoint phase ${signedPayload.payload.checkpointPhase} is not part of the GJKR phase plan`,
            );
        }
    }
};

/**
 * Resolves and validates the unique threshold-supported checkpoint for one
 * closed DKG phase.
 */
export const resolveVerifiedPhaseCheckpoint = async (
    input: ResolvePhaseCheckpointInput,
): Promise<FinalizedPhaseCheckpoint> => {
    const supported = collectCheckpointVariants(
        input.transcript,
        input.checkpointPhase,
    ).filter((entry) => entry.signatures.length >= input.threshold);

    if (supported.length === 0) {
        throw new InvalidPayloadError(
            `Missing threshold-supported phase checkpoint for phase ${input.checkpointPhase}`,
        );
    }
    if (supported.length > 1) {
        throw new InvalidPayloadError(
            `Observed multiple threshold-supported phase checkpoints for phase ${input.checkpointPhase}`,
        );
    }

    const checkpoint = supported[0];
    const qualifiedParticipantIndices =
        checkpoint.payload.qualifiedParticipantIndices;

    assertUniqueSortedParticipantIndices(
        qualifiedParticipantIndices,
        input.participantCount,
        `Phase ${input.checkpointPhase} checkpoint qualified participant`,
    );
    if (
        !sameParticipantIndexList(
            qualifiedParticipantIndices,
            input.expectedQualifiedParticipantIndices,
        )
    ) {
        throw new InvalidPayloadError(
            `Phase ${input.checkpointPhase} checkpoint qualified participant set does not match the verifier-computed active participant set`,
        );
    }
    if (qualifiedParticipantIndices.length < input.threshold) {
        throw new InvalidPayloadError(
            `Checkpoint qualified participant set for phase ${input.checkpointPhase} must contain at least ${input.threshold} participants`,
        );
    }

    const expectedSnapshotHash = await hashProtocolPhaseSnapshot(
        input.transcript.map((entry) => entry.payload),
        input.checkpointPhase,
    );
    if (checkpoint.payload.checkpointTranscriptHash !== expectedSnapshotHash) {
        throw new InvalidPayloadError(
            `Phase ${input.checkpointPhase} checkpoint transcript hash does not match the signed transcript snapshot`,
        );
    }

    assertIndexSubset(
        checkpoint.signers,
        input.signerUniverse,
        `Phase ${input.checkpointPhase} checkpoint signer`,
    );

    const qualifiedParticipantSet = new Set(qualifiedParticipantIndices);
    for (const signer of checkpoint.signers) {
        if (!qualifiedParticipantSet.has(signer)) {
            throw new InvalidPayloadError(
                `Phase ${input.checkpointPhase} checkpoint signer ${signer} is not part of the checkpoint qualified participant set`,
            );
        }
    }

    return checkpoint;
};
