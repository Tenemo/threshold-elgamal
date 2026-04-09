import {
    assertValidParticipantIndex,
    majorityThreshold,
} from '../core/index.js';
import type {
    ComplaintPayload,
    ComplaintResolutionPayload,
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
import { expectedDkgPhase } from './phase-plan.js';
import type {
    DKGProtocol,
    DKGState,
    DKGTransition,
    MajorityDKGConfigInput,
} from './types.js';

const protocolLabel = (protocol: DKGProtocol): string =>
    protocol === 'gjkr' ? 'GJKR' : 'Joint-Feldman';

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

export const createMajorityDkgState = (
    config: MajorityDKGConfigInput,
    protocol: DKGProtocol,
): DKGState =>
    createBaseState({
        ...config,
        protocol,
        threshold: majorityThreshold(config.participantCount),
    });

export const processMajorityDkgPayload = (
    state: DKGState,
    signedPayload: SignedPayload,
): DKGTransition => {
    const label = protocolLabel(state.config.protocol);

    if (state.phase === 'aborted' || state.phase === 'completed') {
        return withError(
            state,
            'terminal-state',
            `${label} is already in a terminal state`,
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
        state.config.protocol,
        signedPayload.payload.messageType,
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
    const complaints = complaintsFromTranscript(nextTranscriptState.transcript);
    const qual = computeQual(
        state.config.participantCount,
        complaints,
        complaintResolutionsFromTranscript(nextTranscriptState.transcript),
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

    const confirmedParticipants = new Set(
        nextTranscriptState.transcript
            .filter(
                (item) =>
                    item.payload.messageType === 'key-derivation-confirmation',
            )
            .map((item) => item.payload.participantIndex),
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
