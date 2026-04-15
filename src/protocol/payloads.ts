import { utf8ToBytes } from '../core/index';
import { bytesToHex, encodeForChallenge } from '../serialize/encoding';

import { canonicalizeJson } from './canonical-json';
import {
    assertValidProtocolVersion,
    SHIPPED_PROTOCOL_VERSION,
} from './manifest';
import type { ProtocolPayload, SignedPayload } from './types';

/** Fixed domain separator for protocol-payload signatures. */
const PROTOCOL_SIGNATURE_DOMAIN = 'threshold-elgamal/protocol-signature';

export type ProtocolPayloadInput<
    TPayload extends ProtocolPayload = ProtocolPayload,
> = Omit<TPayload, 'protocolVersion'> & {
    readonly protocolVersion?: string;
};

export const attachProtocolVersion = <TPayload extends ProtocolPayload>(
    payload: ProtocolPayloadInput<TPayload>,
): TPayload =>
    ({
        ...payload,
        protocolVersion: assertValidProtocolVersion(
            payload.protocolVersion ?? SHIPPED_PROTOCOL_VERSION,
            'Protocol payload version',
        ),
    }) as TPayload;

/**
 * Computes the canonical slot key used for idempotence and equivocation checks.
 *
 * @param payload Unsigned protocol payload.
 * @returns Stable slot key for the payload author and message slot.
 */
export const payloadSlotKey = (payload: ProtocolPayload): string => {
    const prefix = `${payload.sessionId}:${payload.phase}:${payload.participantIndex}:${payload.messageType}`;

    switch (payload.messageType) {
        case 'ballot-close':
            return `${payload.sessionId}:${payload.phase}:${payload.messageType}`;
        case 'encrypted-dual-share':
            return `${prefix}:${payload.recipientIndex}`;
        case 'complaint':
            return `${prefix}:${payload.dealerIndex}:${payload.envelopeId}`;
        case 'complaint-resolution':
            return `${prefix}:${payload.dealerIndex}:${payload.complainantIndex}:${payload.envelopeId}`;
        case 'phase-checkpoint':
            return `${prefix}:${payload.checkpointPhase}`;
        case 'ballot-submission':
            return `${prefix}:${payload.optionIndex}`;
        case 'decryption-share':
        case 'tally-publication':
            return `${prefix}:${payload.optionIndex}`;
        default:
            return prefix;
    }
};

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
 * Serializes the payload bytes that are covered by the outer Ed25519 signature.
 *
 * The signature preimage is domain-separated and version-bound so that protocol
 * payload signatures are not re-used across transcript families or protocol
 * revisions.
 *
 * @param payload Unsigned protocol payload.
 * @param bigintByteLength Fixed byte width used for any bigint fields.
 * @returns Canonical signature preimage bytes.
 */
export const signedProtocolPayloadBytes = (
    payload: ProtocolPayload,
    bigintByteLength?: number,
): Uint8Array => {
    assertValidProtocolVersion(
        payload.protocolVersion,
        'Protocol payload version',
    );

    return encodeForChallenge(
        PROTOCOL_SIGNATURE_DOMAIN,
        payload.protocolVersion,
        canonicalUnsignedPayloadBytes(payload, bigintByteLength),
    );
};

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
