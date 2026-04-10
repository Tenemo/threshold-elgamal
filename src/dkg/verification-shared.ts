import {
    InvalidPayloadError,
    assertInSubgroupOrIdentity,
    type CryptoGroup,
} from '../core/index.js';
import { decodePoint } from '../core/ristretto.js';
import type { EncodedPoint } from '../core/types.js';
import type { ProofContext } from '../proofs/index.js';
import { classifySlotConflict } from '../protocol/payloads.js';
import type {
    FeldmanCommitmentPayload,
    SignedPayload,
} from '../protocol/types.js';

import { isPhaseCheckpointPayload } from './checkpoints.js';
import { expectedDkgPhase } from './phase-plan.js';
import type { VerifyDKGTranscriptInput } from './verification-types.js';

export const assertUniqueSlots = (
    transcript: readonly SignedPayload[],
): void => {
    for (let leftIndex = 0; leftIndex < transcript.length; leftIndex += 1) {
        for (
            let rightIndex = leftIndex + 1;
            rightIndex < transcript.length;
            rightIndex += 1
        ) {
            const relation = classifySlotConflict(
                transcript[leftIndex],
                transcript[rightIndex],
            );
            if (relation === 'equivocation') {
                throw new InvalidPayloadError(
                    'A different payload for the same canonical slot was observed',
                );
            }
        }
    }
};

export const groupByParticipant = <
    TPayload extends { readonly participantIndex: number },
>(
    payloads: readonly TPayload[],
): Map<number, TPayload[]> => {
    const map = new Map<number, TPayload[]>();
    for (const payload of payloads) {
        const existing = map.get(payload.participantIndex) ?? [];
        existing.push(payload);
        map.set(payload.participantIndex, existing);
    }
    return map;
};

export const requireExactlyOnePayload = <TPayload>(
    payloads: readonly TPayload[],
    label: string,
): TPayload => {
    if (payloads.length !== 1) {
        throw new InvalidPayloadError(`${label} requires exactly one payload`);
    }

    return payloads[0];
};

export const parseCommitmentVector = (
    commitments: readonly string[],
    expectedLength: number,
    _group: CryptoGroup,
    label: string,
): readonly EncodedPoint[] => {
    if (commitments.length !== expectedLength) {
        throw new InvalidPayloadError(
            `${label} must contain exactly ${expectedLength} commitments`,
        );
    }

    const parsed = commitments.map((commitment) => {
        assertInSubgroupOrIdentity(commitment);
        return commitment as EncodedPoint;
    });
    if (
        decodePoint(parsed[parsed.length - 1], `${label} last commitment`).is0()
    ) {
        throw new InvalidPayloadError(
            `${label} must commit to the exact claimed polynomial degree`,
        );
    }

    return parsed;
};

export const buildSchnorrContext = (
    payload: FeldmanCommitmentPayload,
    protocolVersion: string,
    coefficientIndex: number,
    group: CryptoGroup,
): ProofContext => ({
    protocolVersion,
    suiteId: group.name,
    manifestHash: payload.manifestHash,
    sessionId: payload.sessionId,
    label: 'feldman-coefficient-proof',
    participantIndex: payload.participantIndex,
    coefficientIndex,
});

export const complaintResolutionKey = (
    complainantIndex: number,
    dealerIndex: number,
    envelopeId: string,
): string => `${complainantIndex}:${dealerIndex}:${envelopeId}`;

export const encryptedShareSlotKey = (
    dealerIndex: number,
    recipientIndex: number,
): string => `${dealerIndex}:${recipientIndex}`;

export const allParticipantIndices = (
    participantCount: number,
): readonly number[] =>
    Array.from({ length: participantCount }, (_value, index) => index + 1);

export const validateParticipantIndex = (
    index: number,
    participantCount: number,
    label: string,
): void => {
    if (!Number.isInteger(index) || index < 1 || index > participantCount) {
        throw new InvalidPayloadError(
            `${label} ${index} must satisfy 1 <= j <= n (n = ${participantCount})`,
        );
    }
};

export const assertUniqueSortedParticipantIndices = (
    indices: readonly number[],
    participantCount: number,
    label: string,
): void => {
    let previous = 0;
    const seen = new Set<number>();

    for (const index of indices) {
        validateParticipantIndex(index, participantCount, label);
        if (seen.has(index)) {
            throw new InvalidPayloadError(`${label} indices must be unique`);
        }
        if (index <= previous) {
            throw new InvalidPayloadError(
                `${label} indices must be strictly increasing`,
            );
        }
        seen.add(index);
        previous = index;
    }
};

export const validateTranscriptShape = (
    input: VerifyDKGTranscriptInput,
    manifestHash: string,
): void => {
    for (const signedPayload of input.transcript) {
        const expected = expectedDkgPhase(
            signedPayload.payload.messageType,
            isPhaseCheckpointPayload(signedPayload)
                ? signedPayload.payload
                : undefined,
        );
        if (expected === null || signedPayload.payload.phase !== expected) {
            throw new InvalidPayloadError(
                'Payload phase does not match the GJKR phase plan',
            );
        }
        if (signedPayload.payload.sessionId !== input.sessionId) {
            throw new InvalidPayloadError(
                'Payload session does not match the verification input',
            );
        }
        if (signedPayload.payload.manifestHash !== manifestHash) {
            throw new InvalidPayloadError(
                'Payload manifest hash does not match the verification input',
            );
        }
    }
};

export const assertIndexSubset = (
    indices: readonly number[],
    allowed: ReadonlySet<number>,
    label: string,
): void => {
    for (const index of indices) {
        if (!allowed.has(index)) {
            throw new InvalidPayloadError(
                `${label} ${index} is not part of the allowed participant set`,
            );
        }
    }
};
