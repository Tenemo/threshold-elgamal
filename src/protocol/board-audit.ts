import { InvalidPayloadError } from '../core/index.js';

import { compareProtocolPayloads } from './ordering.js';
import {
    canonicalUnsignedPayloadBytes,
    classifySlotConflict,
    payloadSlotKey,
} from './payloads.js';
import {
    formatSessionFingerprint,
    hashProtocolTranscript,
} from './transcript.js';
import type { ProtocolPayload, SignedPayload } from './types.js';

/** Classification for one canonical bulletin-board slot. */
export type BoardSlotStatus = 'unique' | 'idempotent-retransmission';

/** Audit result for one canonical bulletin-board slot. */
export type BoardSlotAudit = {
    readonly slotKey: string;
    readonly occurrences: number;
    readonly status: BoardSlotStatus;
};

/** Canonical digest summary for one protocol phase. */
export type PhaseDigest = {
    readonly phase: number;
    readonly digest: string;
    readonly payloadCount: number;
};

/** Deterministic audit result for a set of signed protocol payloads. */
export type BoardAudit<TPayload extends ProtocolPayload = ProtocolPayload> = {
    readonly acceptedPayloads: readonly SignedPayload<TPayload>[];
    readonly ceremonyDigest: string;
    readonly fingerprint: string;
    readonly phaseDigests: readonly PhaseDigest[];
    readonly slotAudit: readonly BoardSlotAudit[];
};

const compareSignedPayloads = (
    left: SignedPayload,
    right: SignedPayload,
): number => {
    const payloadOrder = compareProtocolPayloads(left.payload, right.payload);
    if (payloadOrder !== 0) {
        return payloadOrder;
    }

    if (left.signature < right.signature) {
        return -1;
    }
    if (left.signature > right.signature) {
        return 1;
    }

    return 0;
};

const chooseRepresentative = <TPayload extends ProtocolPayload>(
    payloads: readonly SignedPayload<TPayload>[],
): SignedPayload<TPayload> => [...payloads].sort(compareSignedPayloads)[0];

const acceptedUnsignedPayloads = <TPayload extends ProtocolPayload>(
    acceptedPayloads: readonly SignedPayload<TPayload>[],
): readonly ProtocolPayload[] =>
    acceptedPayloads.map((payload) => payload.payload);

/**
 * Audits signed payloads by canonical slot, rejecting equivocation and
 * collapsing exact retransmissions to one representative payload.
 *
 * @param signedPayloads Signed payloads to audit.
 * @returns Deterministic audit output with accepted payloads and digests.
 */
export const auditSignedPayloads = async <TPayload extends ProtocolPayload>(
    signedPayloads: readonly SignedPayload<TPayload>[],
): Promise<BoardAudit<TPayload>> => {
    const sortedPayloads = [...signedPayloads].sort(compareSignedPayloads);
    const payloadsBySlot = new Map<string, SignedPayload<TPayload>[]>();

    for (const signedPayload of sortedPayloads) {
        const slotKey = payloadSlotKey(signedPayload.payload);
        const existing = payloadsBySlot.get(slotKey) ?? [];
        existing.push(signedPayload);
        payloadsBySlot.set(slotKey, existing);
    }

    const acceptedPayloads: SignedPayload<TPayload>[] = [];
    const slotAudit: BoardSlotAudit[] = [];

    for (const [slotKey, slotPayloads] of payloadsBySlot.entries()) {
        const representative = slotPayloads[0];

        for (const candidate of slotPayloads.slice(1)) {
            const classification = classifySlotConflict(
                representative,
                candidate,
            );
            if (classification === 'equivocation') {
                throw new InvalidPayloadError(
                    `Detected equivocation for canonical slot ${slotKey}`,
                );
            }
        }

        acceptedPayloads.push(chooseRepresentative(slotPayloads));
        slotAudit.push({
            slotKey,
            occurrences: slotPayloads.length,
            status:
                slotPayloads.length === 1
                    ? 'unique'
                    : 'idempotent-retransmission',
        });
    }

    acceptedPayloads.sort(compareSignedPayloads);
    slotAudit.sort((left, right) => left.slotKey.localeCompare(right.slotKey));

    const unsignedPayloads = acceptedUnsignedPayloads(acceptedPayloads);
    const ceremonyDigest = await hashProtocolTranscript(unsignedPayloads);
    const phaseNumbers = [
        ...new Set(unsignedPayloads.map((payload) => payload.phase)),
    ].sort((left, right) => left - right);
    const phaseDigests = await Promise.all(
        phaseNumbers.map(async (phase): Promise<PhaseDigest> => {
            const phasePayloads = unsignedPayloads.filter(
                (payload) => payload.phase === phase,
            );

            return {
                phase,
                digest: await hashProtocolTranscript(phasePayloads),
                payloadCount: phasePayloads.length,
            };
        }),
    );

    return {
        acceptedPayloads,
        ceremonyDigest,
        fingerprint: formatSessionFingerprint(ceremonyDigest),
        phaseDigests,
        slotAudit,
    };
};

/**
 * Verifies that each supplied payload is present in the accepted audited board
 * under its canonical slot key.
 *
 * @param payloads Payloads expected to be included.
 * @param audit Board audit to check against.
 */
export const assertPayloadsIncludedInAudit = <TPayload extends ProtocolPayload>(
    payloads: readonly SignedPayload<TPayload>[],
    audit: BoardAudit<TPayload>,
): void => {
    const acceptedBySlot = new Map(
        audit.acceptedPayloads.map((payload) => [
            payloadSlotKey(payload.payload),
            canonicalUnsignedPayloadBytes(payload.payload),
        ]),
    );

    for (const payload of payloads) {
        const slotKey = payloadSlotKey(payload.payload);
        const acceptedBytes = acceptedBySlot.get(slotKey);

        if (acceptedBytes === undefined) {
            throw new InvalidPayloadError(
                `Payload for canonical slot ${slotKey} is missing from the audited board`,
            );
        }

        const candidateBytes = canonicalUnsignedPayloadBytes(payload.payload);
        if (candidateBytes.length !== acceptedBytes.length) {
            throw new InvalidPayloadError(
                `Payload inclusion mismatch for canonical slot ${slotKey}`,
            );
        }
        for (let index = 0; index < candidateBytes.length; index += 1) {
            if (candidateBytes[index] !== acceptedBytes[index]) {
                throw new InvalidPayloadError(
                    `Payload inclusion mismatch for canonical slot ${slotKey}`,
                );
            }
        }
    }
};
