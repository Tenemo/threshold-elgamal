import {
    assertMajorityThreshold,
    assertValidParticipantIndex,
} from '../core/index.js';
import type {
    ComplaintPayload,
    ComplaintResolutionPayload,
    ManifestAcceptancePayload,
    SignedPayload,
} from '../protocol/types.js';

import {
    finalCheckpointPhase,
    isPhaseCheckpointPayload,
    requiredCheckpointPhases,
    resolveFinalizedPhaseCheckpoint,
    type FinalizedPhaseCheckpoint,
} from './checkpoints.js';
import {
    appendTranscriptPayload,
    computeQual,
    createBaseState,
    reduceQualByComplaints,
    validateCommonPayload,
    withError,
} from './complaints.js';
import { expectedDkgPhase } from './phase-plan.js';
import { validateAuthenticatedPayload } from './reducer-auth.js';
import type { DKGState, DKGTransition, DKGConfigInput } from './types.js';

const acceptedParticipants = (
    transcript: readonly SignedPayload[],
): readonly number[] =>
    transcript
        .filter(
            (item): item is SignedPayload<ManifestAcceptancePayload> =>
                item.payload.messageType === 'manifest-acceptance',
        )
        .map((item) => item.payload.participantIndex)
        .sort((left, right) => left - right);

const contiguousFinalizedCheckpoints = (
    transcript: readonly SignedPayload[],
    threshold: number,
): readonly FinalizedPhaseCheckpoint[] => {
    const resolved: FinalizedPhaseCheckpoint[] = [];

    for (const checkpointPhase of requiredCheckpointPhases()) {
        const checkpoint = resolveFinalizedPhaseCheckpoint(
            transcript,
            checkpointPhase,
            threshold,
        );
        if (checkpoint === null) {
            break;
        }
        resolved.push(checkpoint);
    }

    return resolved;
};

const latestCheckpointQual = (
    transcript: readonly SignedPayload[],
    threshold: number,
): readonly number[] | null => {
    const checkpoints = contiguousFinalizedCheckpoints(transcript, threshold);

    return (
        checkpoints[checkpoints.length - 1]?.payload.qualParticipantIndices ??
        null
    );
};

const hasCheckpointFlow = (
    transcript: readonly SignedPayload[],
    payload?: SignedPayload,
): boolean =>
    transcript.some(isPhaseCheckpointPayload) ||
    (payload !== undefined && isPhaseCheckpointPayload(payload));

const complaintsFromTranscript = (
    transcript: readonly SignedPayload[],
): readonly ComplaintPayload[] =>
    transcript
        .filter(
            (item): item is SignedPayload<ComplaintPayload> =>
                item.payload.messageType === 'complaint',
        )
        .map((item) => item.payload);

const complaintResolutionsFromTranscript = (
    transcript: readonly SignedPayload[],
): readonly ComplaintResolutionPayload[] =>
    transcript
        .filter(
            (item): item is SignedPayload<ComplaintResolutionPayload> =>
                item.payload.messageType === 'complaint-resolution',
        )
        .map((item) => item.payload);

export const createMajorityDkgState = (config: DKGConfigInput): DKGState => {
    assertMajorityThreshold(config.threshold, config.participantCount);

    return createBaseState(config);
};

export const processMajorityDkgPayload = (
    state: DKGState,
    signedPayload: SignedPayload,
): DKGTransition => {
    const label = 'GJKR';

    if (state.phase === 'aborted' || state.phase === 'completed') {
        return withError(
            state,
            'terminal-state',
            `${label} is already in a terminal state`,
        );
    }

    if (
        isPhaseCheckpointPayload(signedPayload) &&
        !requiredCheckpointPhases().includes(
            signedPayload.payload.checkpointPhase,
        )
    ) {
        return withError(
            state,
            'checkpoint-phase-out-of-range',
            `Checkpoint phase ${signedPayload.payload.checkpointPhase} is not part of the ${label} phase plan`,
        );
    }

    const validationError = validateCommonPayload(state, signedPayload);
    if (validationError !== null) {
        return {
            newState: state,
            outgoingPayloads: [],
            errors: [validationError],
        };
    }

    const phase = expectedDkgPhase(
        signedPayload.payload.messageType,
        isPhaseCheckpointPayload(signedPayload)
            ? signedPayload.payload
            : undefined,
    );
    if (phase === null || signedPayload.payload.phase !== phase) {
        return withError(
            state,
            'phase-mismatch',
            `Payload phase does not match the ${label} phase plan`,
        );
    }

    assertValidParticipantIndex(
        signedPayload.payload.participantIndex,
        state.config.participantCount,
    );

    const authenticationError = validateAuthenticatedPayload(
        state.transcript,
        signedPayload,
    );
    if (authenticationError !== null) {
        return {
            newState: state,
            outgoingPayloads: [],
            errors: [authenticationError],
        };
    }

    if (isPhaseCheckpointPayload(signedPayload)) {
        if (
            signedPayload.payload.checkpointPhase > 0 &&
            resolveFinalizedPhaseCheckpoint(
                state.transcript,
                signedPayload.payload.checkpointPhase - 1,
                state.config.threshold,
            ) === null
        ) {
            return withError(
                state,
                'checkpoint-prerequisite-required',
                'Each checkpoint requires the previous DKG phase to be checkpointed first',
            );
        }
    } else if (phase > 0) {
        if (hasCheckpointFlow(state.transcript, signedPayload)) {
            if (
                resolveFinalizedPhaseCheckpoint(
                    state.transcript,
                    phase - 1,
                    state.config.threshold,
                ) === null
            ) {
                return withError(
                    state,
                    'phase-checkpoint-required',
                    `Phase ${phase} requires a finalized checkpoint for phase ${phase - 1}`,
                );
            }
        } else if (
            acceptedParticipants(state.transcript).length !==
            state.config.participantCount
        ) {
            return withError(
                state,
                'manifest-acceptance-required',
                'Setup is gated on unanimous manifest acceptance',
            );
        }
    }

    const appended = appendTranscriptPayload(state, signedPayload);
    if (appended.errors.length > 0 || appended.newState.phase === 'aborted') {
        return appended;
    }
    if (appended.newState === state) {
        return appended;
    }

    const nextTranscriptState = appended.newState;
    const manifestAccepted = acceptedParticipants(
        nextTranscriptState.transcript,
    );
    const complaints = complaintsFromTranscript(nextTranscriptState.transcript);
    const latestCheckpointQualIndices = latestCheckpointQual(
        nextTranscriptState.transcript,
        state.config.threshold,
    );
    const qual =
        latestCheckpointQualIndices === null
            ? computeQual(
                  state.config.participantCount,
                  complaints,
                  complaintResolutionsFromTranscript(
                      nextTranscriptState.transcript,
                  ),
              )
            : latestCheckpointQualIndices.length > 0
              ? reduceQualByComplaints(
                    latestCheckpointQualIndices,
                    complaints,
                    complaintResolutionsFromTranscript(
                        nextTranscriptState.transcript,
                    ),
                )
              : latestCheckpointQualIndices;

    if (qual.length < state.config.threshold) {
        return {
            newState: {
                ...nextTranscriptState,
                phase: 'aborted',
                manifestAccepted,
                complaints,
                qual,
                abortReason: 'qual-too-small',
            },
            outgoingPayloads: [],
            errors: [
                {
                    code: 'qual-too-small',
                    message: 'QUAL fell below the reconstruction threshold',
                },
            ],
        };
    }

    const confirmedParticipants = new Set(
        nextTranscriptState.transcript
            .filter(
                (item) =>
                    item.payload.messageType === 'key-derivation-confirmation',
            )
            .map((item) => item.payload.participantIndex),
    );
    const contiguousCheckpoints = contiguousFinalizedCheckpoints(
        nextTranscriptState.transcript,
        state.config.threshold,
    );
    const completedByCheckpoint =
        contiguousCheckpoints[contiguousCheckpoints.length - 1]?.payload
            .checkpointPhase === finalCheckpointPhase();
    const completed =
        completedByCheckpoint ||
        (!hasCheckpointFlow(nextTranscriptState.transcript) &&
            qual.every((index) => confirmedParticipants.has(index)));

    return {
        newState: {
            ...nextTranscriptState,
            phase: completed
                ? 'completed'
                : (signedPayload.payload.phase as 0 | 1 | 2 | 3 | 4),
            manifestAccepted,
            complaints,
            qual,
        },
        outgoingPayloads: [],
        errors: [],
    };
};
