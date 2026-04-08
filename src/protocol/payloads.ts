import { utf8ToBytes } from '../core/index.js';
import { bytesToHex } from '../serialize/index.js';

import { canonicalizeJson } from './canonical-json.js';
import type { ProtocolPayload, SignedPayload } from './types.js';

/**
 * Computes the canonical slot key used for idempotence and equivocation checks.
 *
 * @param payload Unsigned protocol payload.
 * @returns Stable slot key for the payload author and phase slot.
 */
export const payloadSlotKey = (payload: ProtocolPayload): string =>
    `${payload.sessionId}:${payload.phase}:${payload.participantIndex}:${payload.messageType}`;

/**
 * Serializes the unsigned payload into canonical bytes.
 *
 * @param payload Unsigned protocol payload.
 * @param bigintByteLength Fixed byte width used for any bigint fields.
 * @returns Canonical unsigned payload bytes.
 */
export const canonicalUnsignedPayloadBytes = (
    payload: ProtocolPayload,
    bigintByteLength?: number,
): Uint8Array => utf8ToBytes(canonicalizeJson(payload, { bigintByteLength }));

/**
 * Classifies how two signed payloads for the same slot relate to one another.
 *
 * Payloads with identical unsigned canonical bytes are idempotent
 * retransmissions even when the signatures differ.
 *
 * @param left First signed payload.
 * @param right Second signed payload.
 * @param bigintByteLength Fixed byte width used for any bigint fields.
 * @returns `distinct`, `idempotent`, or `equivocation`.
 */
export const classifySlotConflict = (
    left: SignedPayload,
    right: SignedPayload,
    bigintByteLength?: number,
): 'distinct' | 'idempotent' | 'equivocation' => {
    if (payloadSlotKey(left.payload) !== payloadSlotKey(right.payload)) {
        return 'distinct';
    }

    const leftBytes = bytesToHex(
        canonicalUnsignedPayloadBytes(left.payload, bigintByteLength),
    );
    const rightBytes = bytesToHex(
        canonicalUnsignedPayloadBytes(right.payload, bigintByteLength),
    );

    return leftBytes === rightBytes ? 'idempotent' : 'equivocation';
};
