import { classifySlotConflict } from '../protocol/payloads.js';
import type {
    ComplaintPayload,
    ComplaintResolutionPayload,
    SignedPayload,
} from '../protocol/types.js';

import type { DKGConfig, DKGError, DKGState, DKGTransition } from './types.js';

const allParticipants = (participantCount: number): readonly number[] =>
    Array.from({ length: participantCount }, (_value, index) => index + 1);

const complaintKey = (
    complainantIndex: number,
    dealerIndex: number,
    envelopeId: string,
): string => `${complainantIndex}:${dealerIndex}:${envelopeId}`;

const isParticipantIndexInRange = (
    index: number,
    participantCount: number,
): boolean =>
    Number.isInteger(index) && index >= 1 && index <= participantCount;

/**
 * Computes QUAL from the frozen participant roster and accepted complaint set.
 *
 * False complainants remain in QUAL. Dealers targeted by complaints are
 * removed unless a dealer-authored complaint resolution matches the same
 * complainant, dealer, and envelope slot.
 *
 * @param participantCount Total participant count `n`.
 * @param complaints Accepted complaints.
 * @param complaintResolutions Complaint resolutions already accepted into the
 * transcript.
 * @returns Sorted QUAL participant indices.
 */
export const computeQual = (
    participantCount: number,
    complaints: readonly ComplaintPayload[],
    complaintResolutions: readonly ComplaintResolutionPayload[] = [],
): readonly number[] => {
    const complaintKeys = new Set(
        complaints.map((complaint) =>
            complaintKey(
                complaint.participantIndex,
                complaint.dealerIndex,
                complaint.envelopeId,
            ),
        ),
    );
    const resolvedComplaints = new Set(
        complaintResolutions
            .filter(
                (resolution) =>
                    resolution.participantIndex === resolution.dealerIndex &&
                    isParticipantIndexInRange(
                        resolution.dealerIndex,
                        participantCount,
                    ) &&
                    isParticipantIndexInRange(
                        resolution.complainantIndex,
                        participantCount,
                    ) &&
                    complaintKeys.has(
                        complaintKey(
                            resolution.complainantIndex,
                            resolution.dealerIndex,
                            resolution.envelopeId,
                        ),
                    ),
            )
            .map((resolution) =>
                complaintKey(
                    resolution.complainantIndex,
                    resolution.dealerIndex,
                    resolution.envelopeId,
                ),
            ),
    );
    const disqualifiedDealers = new Set(
        complaints
            .filter(
                (complaint) =>
                    !resolvedComplaints.has(
                        complaintKey(
                            complaint.participantIndex,
                            complaint.dealerIndex,
                            complaint.envelopeId,
                        ),
                    ),
            )
            .map((complaint) => complaint.dealerIndex),
    );

    return allParticipants(participantCount).filter(
        (index) => !disqualifiedDealers.has(index),
    );
};

/**
 * Creates the initial empty DKG reducer state.
 *
 * @param config DKG configuration.
 * @returns Reducer state before any transcript payloads are processed.
 */
export const createBaseState = (config: DKGConfig): DKGState => ({
    config,
    phase: 0,
    manifestAccepted: [],
    qual: allParticipants(config.participantCount),
    complaints: [],
    transcript: [],
});

/**
 * Builds a no-op transition carrying one structured reducer error.
 *
 * @param state Current reducer state.
 * @param code Stable error code.
 * @param message Human-readable error message.
 * @returns Transition preserving `state` and reporting one error.
 */
export const withError = (
    state: DKGState,
    code: string,
    message: string,
): DKGTransition => ({
    newState: state,
    outgoingPayloads: [],
    errors: [{ code, message }],
});

/**
 * Validates session-level fields shared by every DKG payload.
 *
 * @param state Current reducer state.
 * @param signedPayload Incoming signed payload.
 * @returns Structured validation error, or `null` when the payload matches.
 */
export const validateCommonPayload = (
    state: DKGState,
    signedPayload: SignedPayload,
): DKGError | null => {
    if (signedPayload.payload.sessionId !== state.config.sessionId) {
        return {
            code: 'session-mismatch',
            message: 'Payload session does not match the DKG configuration',
        };
    }

    if (signedPayload.payload.manifestHash !== state.config.manifestHash) {
        return {
            code: 'manifest-mismatch',
            message:
                'Payload manifest hash does not match the DKG configuration',
        };
    }

    return null;
};

/**
 * Appends one payload to the transcript while enforcing slot idempotence and
 * equivocation detection.
 *
 * @param state Current reducer state.
 * @param signedPayload Incoming signed payload.
 * @returns Transition with either an updated transcript or an abort.
 */
export const appendTranscriptPayload = (
    state: DKGState,
    signedPayload: SignedPayload,
): DKGTransition => {
    for (const existing of state.transcript) {
        const classification = classifySlotConflict(existing, signedPayload);
        if (classification === 'idempotent') {
            return {
                newState: state,
                outgoingPayloads: [],
                errors: [],
            };
        }

        if (classification === 'equivocation') {
            return {
                newState: {
                    ...state,
                    phase: 'aborted',
                    abortReason: 'equivocation-detected',
                },
                outgoingPayloads: [],
                errors: [
                    {
                        code: 'equivocation',
                        message:
                            'A different payload for the same canonical slot was observed',
                    },
                ],
            };
        }
    }

    return {
        newState: {
            ...state,
            transcript: [...state.transcript, signedPayload],
        },
        outgoingPayloads: [],
        errors: [],
    };
};
