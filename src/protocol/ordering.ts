import { bytesToHex } from '../serialize/index.js';

import { canonicalUnsignedPayloadBytes, payloadSlotKey } from './payloads.js';
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
 * The sort order is `sessionId ASC, phase ASC, participantIndex ASC,
 * messageType ASC`, followed by message-type-specific slot fields and finally
 * canonical payload bytes to guarantee a total order.
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

    if (left.messageType !== right.messageType) {
        return compareStrings(left.messageType, right.messageType);
    }

    const leftSlotKey = payloadSlotKey(left);
    const rightSlotKey = payloadSlotKey(right);

    if (leftSlotKey !== rightSlotKey) {
        return compareStrings(leftSlotKey, rightSlotKey);
    }

    return compareStrings(
        bytesToHex(canonicalUnsignedPayloadBytes(left)),
        bytesToHex(canonicalUnsignedPayloadBytes(right)),
    );
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
