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
        case 'pedersen-commitment':
        case 'encrypted-dual-share':
            return 1;
        case 'complaint':
        case 'complaint-resolution':
            return 2;
        case 'feldman-commitment':
        case 'feldman-share-reveal':
            return 3;
        case 'key-derivation-confirmation':
            return 4;
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
 * Creates an empty GJKR state.
 *
 * @param config DKG configuration.
 * @returns Initial GJKR state.
 */
export const createGjkrState = (config: MajorityDKGConfigInput): DKGState =>
    createBaseState({
        ...config,
        protocol: 'gjkr',
        threshold: majorityThreshold(config.participantCount),
    });

/**
 * Processes one signed payload through the GJKR log reducer.
 *
 * @param state Current GJKR state.
 * @param signedPayload Incoming signed payload.
 * @returns Deterministic state transition result.
 */
export const processGjkrPayload = (
    state: DKGState,
    signedPayload: SignedPayload,
): DKGTransition => {
    if (state.phase === 'aborted' || state.phase === 'completed') {
        return withError(
            state,
            'terminal-state',
            'GJKR is already in a terminal state',
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
            'Payload phase does not match the GJKR phase plan',
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
 * Replays a GJKR transcript from the initial state.
 *
 * @param config DKG configuration.
 * @param transcript Signed transcript payloads.
 * @returns Final GJKR state after replay.
 */
export const replayGjkrTranscript = (
    config: MajorityDKGConfigInput,
    transcript: readonly SignedPayload[],
): DKGState => {
    let state = createGjkrState(config);

    for (const payload of transcript) {
        state = processGjkrPayload(state, payload).newState;
    }

    return state;
};
