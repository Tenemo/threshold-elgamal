/**
 * Deterministic bulletin-board audit for signed protocol payloads.
 *
 * This is the layer that collapses exact retransmissions, rejects
 * equivocation, and produces stable digests over the accepted transcript.
 */
import { InvalidPayloadError } from '../core/index';

import { compareProtocolPayloads } from './ordering';
import { classifySlotConflict, payloadSlotKey } from './payloads';
import { formatSessionFingerprint, hashProtocolTranscript } from './transcript';
import type { ProtocolPayload, SignedPayload } from './types';

/** Classification for one canonical bulletin-board slot. */
type BoardSlotStatus = 'unique' | 'idempotent-retransmission';

/** Audit result for one canonical bulletin-board slot. */
type BoardSlotAudit = {
    readonly slotKey: string;
    readonly occurrences: number;
    readonly status: BoardSlotStatus;
};

/** Canonical digest summary for one protocol phase. */
type PhaseDigest = {
    readonly phase: number;
    readonly digest: string;
    readonly payloadCount: number;
};

/**
 * Deterministic audit result for a set of signed protocol payloads.
 *
 * Higher-level verifiers consume this output instead of raw board logs so they
 * can operate on one canonical accepted transcript.
 */
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

const acceptedUnsignedPayloads = <TPayload extends ProtocolPayload>(
    acceptedPayloads: readonly SignedPayload<TPayload>[],
): readonly ProtocolPayload[] =>
    acceptedPayloads.map((payload) => payload.payload);

/**
 * Audits signed payloads by canonical slot, rejecting equivocation and
 * collapsing only exact signed retransmissions to one representative payload.
 *
 * All transcript-level verifiers run this step before they interpret the
 * semantic contents of the board.
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
            if (candidate.signature !== representative.signature) {
                throw new InvalidPayloadError(
                    `Detected non-identical retransmission for canonical slot ${slotKey}`,
                );
            }
        }

        acceptedPayloads.push(representative);
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
