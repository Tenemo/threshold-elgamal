import type {
    PhaseCheckpointPayload,
    SignedPayload,
} from '../protocol/types.js';

import type { DKGProtocol } from './types.js';

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
        qualParticipantIndices: payload.qualParticipantIndices,
    });

const compareNumbers = (left: number, right: number): number => left - right;

/** Returns `true` when the signed payload is a phase checkpoint. */
export const isPhaseCheckpointPayload = (
    payload: SignedPayload,
): payload is SignedPayload<PhaseCheckpointPayload> =>
    payload.payload.messageType === 'phase-checkpoint';

/** Returns the required checkpoint phases for the selected DKG protocol. */
export const requiredCheckpointPhases = (
    protocol: DKGProtocol,
): readonly number[] => (protocol === 'gjkr' ? [0, 1, 2, 3] : [0, 1, 2]);

/** Returns the last required checkpoint phase for the selected DKG protocol. */
export const finalCheckpointPhase = (protocol: DKGProtocol): number =>
    requiredCheckpointPhases(protocol)[
        requiredCheckpointPhases(protocol).length - 1
    ] ?? 0;

/** Groups all checkpoint variants observed for one closed DKG phase. */
export const collectCheckpointVariants = (
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
 * Returns the unique threshold-supported checkpoint variant for one phase, or
 * `null` when no unique threshold-supported checkpoint exists yet.
 */
export const resolveFinalizedPhaseCheckpoint = (
    transcript: readonly SignedPayload[],
    checkpointPhase: number,
    threshold: number,
): FinalizedPhaseCheckpoint | null => {
    const supported = collectCheckpointVariants(
        transcript,
        checkpointPhase,
    ).filter((entry) => entry.signatures.length >= threshold);

    return supported.length === 1 ? supported[0] : null;
};
