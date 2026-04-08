import {
    assertValidParticipantIndex,
    majorityThreshold,
} from '../core/index.js';
import type {
    ManifestAcceptancePayload,
    SignedPayload,
} from '../protocol/types.js';

import {
    appendTranscriptPayload,
    computeQual,
    createBaseState,
    validateCommonPayload,
    withError,
} from './complaints.js';
import type {
    DKGState,
    DKGTransition,
    MajorityDKGConfigInput,
} from './types.js';

const expectedPhase = (
    messageType: SignedPayload['payload']['messageType'],
): number | null => {
    switch (messageType) {
        case 'manifest-publication':
        case 'registration':
        case 'manifest-acceptance':
            return 0;
        case 'feldman-commitment':
        case 'encrypted-dual-share':
            return 1;
        case 'complaint':
        case 'complaint-resolution':
        case 'feldman-share-reveal':
            return 2;
        case 'key-derivation-confirmation':
            return 3;
        case 'pedersen-commitment':
        case 'ballot-submission':
        case 'decryption-share':
        case 'tally-publication':
        case 'ceremony-restart':
            return null;
    }
};

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

/**
 * Creates an empty Joint-Feldman state.
 *
 * @param config DKG configuration.
 * @returns Initial Joint-Feldman state.
 */
export const createJointFeldmanState = (
    config: MajorityDKGConfigInput,
): DKGState =>
    createBaseState({
        ...config,
        protocol: 'joint-feldman',
        threshold: majorityThreshold(config.participantCount),
    });

/**
 * Processes one signed payload through the Joint-Feldman log reducer.
 *
 * @param state Current Joint-Feldman state.
 * @param signedPayload Incoming signed payload.
 * @returns Deterministic state transition result.
 */
export const processJointFeldmanPayload = (
    state: DKGState,
    signedPayload: SignedPayload,
): DKGTransition => {
    if (state.phase === 'aborted' || state.phase === 'completed') {
        return withError(
            state,
            'terminal-state',
            'Joint-Feldman is already in a terminal state',
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

    const phase = expectedPhase(signedPayload.payload.messageType);
    if (phase === null || signedPayload.payload.phase !== phase) {
        return withError(
            state,
            'phase-mismatch',
            'Payload phase does not match the Joint-Feldman phase plan',
        );
    }

    assertValidParticipantIndex(
        signedPayload.payload.participantIndex,
        state.config.participantCount,
    );

    if (
        phase > 0 &&
        acceptedParticipants(state.transcript).length !==
            state.config.participantCount
    ) {
        return withError(
            state,
            'manifest-acceptance-required',
            'Setup is gated on unanimous manifest acceptance',
        );
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
    const complaints = nextTranscriptState.transcript
        .filter(
            (
                item,
            ): item is SignedPayload<
                import('../protocol/types.js').ComplaintPayload
            > => item.payload.messageType === 'complaint',
        )
        .map((item) => item.payload);
    const complaintResolutions = nextTranscriptState.transcript
        .filter(
            (
                item,
            ): item is SignedPayload<
                import('../protocol/types.js').ComplaintResolutionPayload
            > => item.payload.messageType === 'complaint-resolution',
        )
        .map((item) => item.payload);
    const qual = computeQual(
        state.config.participantCount,
        complaints,
        complaintResolutions,
    );

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

    const confirmations = nextTranscriptState.transcript.filter(
        (item) => item.payload.messageType === 'key-derivation-confirmation',
    );
    const confirmedParticipants = new Set(
        confirmations.map((item) => item.payload.participantIndex),
    );
    const completed = qual.every((index) => confirmedParticipants.has(index));

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

/**
 * Replays a Joint-Feldman transcript from the initial state.
 *
 * @param config DKG configuration.
 * @param transcript Signed transcript payloads.
 * @returns Final Joint-Feldman state after replay.
 */
export const replayJointFeldmanTranscript = (
    config: MajorityDKGConfigInput,
    transcript: readonly SignedPayload[],
): DKGState => {
    let state = createJointFeldmanState(config);

    for (const payload of transcript) {
        state = processJointFeldmanPayload(state, payload).newState;
    }

    return state;
};
