import { InvalidPayloadError } from '../core/index.js';

import { auditSignedPayloads } from './board-audit.js';
import type {
    BallotClosePayload,
    BallotSubmissionPayload,
    SignedPayload,
} from './types.js';
import {
    assertPhase,
    assertUniqueSortedIndices,
    assertValidOptionIndex,
    BALLOT_CLOSE_PHASE,
} from './voting-shared.js';

const requireExactlyOnePayload = <TPayload>(
    payloads: readonly TPayload[],
    label: string,
): TPayload => {
    if (payloads.length !== 1) {
        throw new InvalidPayloadError(`${label} requires exactly one payload`);
    }

    return payloads[0];
};

/** Verified organizer-selected ballot cutoff and the counted ballot subset. */
export type VerifiedBallotClose = {
    readonly countedBallotPayloads: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly countedParticipantIndices: readonly number[];
    readonly excludedParticipantIndices: readonly number[];
    readonly payload: SignedPayload<BallotClosePayload>;
};

const completeBallotParticipants = (
    ballotPayloads: readonly SignedPayload<BallotSubmissionPayload>[],
    optionCount: number,
): readonly number[] => {
    const participantOptions = new Map<number, Set<number>>();

    for (const signedPayload of ballotPayloads) {
        const payload = signedPayload.payload;
        assertValidOptionIndex(
            payload.optionIndex,
            optionCount,
            'Ballot submission',
        );

        const options =
            participantOptions.get(payload.participantIndex) ??
            new Set<number>();
        options.add(payload.optionIndex);
        participantOptions.set(payload.participantIndex, options);
    }

    return [...participantOptions.entries()]
        .filter(([, options]) => options.size === optionCount)
        .map(([participantIndex]) => participantIndex)
        .sort((left, right) => left - right);
};

/**
 * Verifies the organizer-signed ballot cutoff and extracts the counted ballot
 * subset used for all later decryption and tally verification.
 */
export const verifyBallotClosePayload = async (input: {
    readonly ballotClosePayloads: readonly SignedPayload<BallotClosePayload>[];
    readonly ballotPayloads: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly manifestHash: string;
    readonly optionCount: number;
    readonly organizerIndex: number;
    readonly participantCount: number;
    readonly sessionId: string;
    readonly threshold: number;
}): Promise<VerifiedBallotClose> => {
    for (const signedPayload of input.ballotClosePayloads) {
        if (signedPayload.payload.messageType !== 'ballot-close') {
            throw new InvalidPayloadError(
                'Ballot close verification only accepts ballot-close payloads',
            );
        }
    }

    const auditedBallotClosePayloads = await auditSignedPayloads(
        input.ballotClosePayloads,
    );
    const closePayload = requireExactlyOnePayload(
        auditedBallotClosePayloads.acceptedPayloads,
        'Ballot close',
    );
    const payload = closePayload.payload;

    assertPhase(payload, BALLOT_CLOSE_PHASE, 'Ballot close');
    if (payload.sessionId !== input.sessionId) {
        throw new InvalidPayloadError(
            'Ballot close session does not match the verification input',
        );
    }
    if (payload.manifestHash !== input.manifestHash) {
        throw new InvalidPayloadError(
            'Ballot close manifest hash does not match the verification input',
        );
    }
    if (payload.participantIndex !== input.organizerIndex) {
        throw new InvalidPayloadError(
            `Ballot close must be signed by organizer ${input.organizerIndex}`,
        );
    }

    assertUniqueSortedIndices(
        payload.includedParticipantIndices,
        'Ballot close participant',
    );
    for (const participantIndex of payload.includedParticipantIndices) {
        if (participantIndex > input.participantCount) {
            throw new InvalidPayloadError(
                `Ballot close participant ${participantIndex} exceeds the registration roster size ${input.participantCount}`,
            );
        }
    }
    if (payload.includedParticipantIndices.length < input.threshold) {
        throw new InvalidPayloadError(
            `Ballot close must include at least ${input.threshold} participants`,
        );
    }

    const completeParticipants = completeBallotParticipants(
        input.ballotPayloads,
        input.optionCount,
    );
    const completeParticipantSet = new Set(completeParticipants);
    for (const participantIndex of payload.includedParticipantIndices) {
        if (!completeParticipantSet.has(participantIndex)) {
            throw new InvalidPayloadError(
                `Ballot close requires a complete ballot from participant ${participantIndex}`,
            );
        }
    }

    const countedParticipantSet = new Set(payload.includedParticipantIndices);
    const countedBallotPayloads = input.ballotPayloads.filter((signedPayload) =>
        countedParticipantSet.has(signedPayload.payload.participantIndex),
    );
    const excludedParticipantIndices = completeParticipants.filter(
        (participantIndex) => !countedParticipantSet.has(participantIndex),
    );

    return {
        countedBallotPayloads,
        countedParticipantIndices: [...payload.includedParticipantIndices],
        excludedParticipantIndices,
        payload: closePayload,
    };
};
