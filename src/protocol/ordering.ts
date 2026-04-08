import type { ProtocolPayload } from './types.js';

const compareStrings = (left: string, right: string): number => {
    if (left < right) {
        return -1;
    }

    if (left > right) {
        return 1;
    }

    return 0;
};

/**
 * Deterministically compares payloads for transcript ordering.
 *
 * The sort order is `phase ASC, participantIndex ASC, messageType ASC`, with
 * `sessionId` used as a stable prefix when cross-session payloads are mixed.
 *
 * @param left Left payload.
 * @param right Right payload.
 * @returns Negative, zero, or positive comparison result.
 */
export const compareProtocolPayloads = (
    left: ProtocolPayload,
    right: ProtocolPayload,
): number => {
    if (left.sessionId !== right.sessionId) {
        return compareStrings(left.sessionId, right.sessionId);
    }

    if (left.phase !== right.phase) {
        return left.phase - right.phase;
    }

    if (left.participantIndex !== right.participantIndex) {
        return left.participantIndex - right.participantIndex;
    }

    return compareStrings(left.messageType, right.messageType);
};

/**
 * Returns a sorted copy of protocol payloads using the canonical transcript
 * ordering rule.
 *
 * @param payloads Payloads to sort.
 * @returns Sorted payload copy.
 */
export const sortProtocolPayloads = (
    payloads: readonly ProtocolPayload[],
): readonly ProtocolPayload[] => [...payloads].sort(compareProtocolPayloads);
