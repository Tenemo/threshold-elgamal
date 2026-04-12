import { bytesToHex } from '../core/bytes';
import { sha256, utf8ToBytes } from '../core/index';

import { canonicalizeJson } from './canonical-json';
import { sortProtocolPayloads } from './ordering';
import type { ProtocolPayload } from './types';

const isProtocolPhasePayload = (payload: ProtocolPayload): boolean =>
    payload.messageType !== 'phase-checkpoint';

/**
 * Canonically serializes the ordered unsigned payload set for a transcript.
 *
 * @param payloads Payloads to include in the transcript.
 * @param bigintByteLength Fixed byte width used for any bigint fields.
 * @returns Canonical transcript bytes.
 */
const canonicalTranscriptBytes = (
    payloads: readonly ProtocolPayload[],
    bigintByteLength?: number,
): Uint8Array =>
    utf8ToBytes(
        canonicalizeJson(sortProtocolPayloads(payloads), {
            bigintByteLength,
        }),
    );

/**
 * Hashes an ordered transcript of unsigned protocol payloads.
 *
 * @param payloads Payloads to include in the transcript.
 * @param bigintByteLength Fixed byte width used for any bigint fields.
 * @returns Lowercase hexadecimal SHA-256 transcript digest.
 */
export const hashProtocolTranscript = async (
    payloads: readonly ProtocolPayload[],
    bigintByteLength?: number,
): Promise<string> =>
    bytesToHex(
        await sha256(canonicalTranscriptBytes(payloads, bigintByteLength)),
    );

/**
 * Returns the canonical unsigned transcript prefix for one closed phase.
 *
 * Phase-checkpoint payloads are excluded so the checkpoint can sign the phase
 * snapshot without circularly including itself.
 *
 * @param payloads Full unsigned transcript payloads.
 * @param phase Highest DKG phase included in the snapshot.
 * @returns Sorted unsigned payloads up to `phase`.
 */
const protocolPhaseSnapshotPayloads = (
    payloads: readonly ProtocolPayload[],
    phase: number,
): readonly ProtocolPayload[] =>
    sortProtocolPayloads(
        payloads.filter(
            (payload) =>
                isProtocolPhasePayload(payload) && payload.phase <= phase,
        ),
    );

/**
 * Hashes the canonical unsigned transcript prefix for one closed phase.
 *
 * @param payloads Full unsigned transcript payloads.
 * @param phase Highest DKG phase included in the snapshot.
 * @param bigintByteLength Fixed byte width used for bigint fields.
 * @returns Lowercase hexadecimal phase-snapshot digest.
 */
export const hashProtocolPhaseSnapshot = async (
    payloads: readonly ProtocolPayload[],
    phase: number,
    bigintByteLength?: number,
): Promise<string> =>
    hashProtocolTranscript(
        protocolPhaseSnapshotPayloads(payloads, phase),
        bigintByteLength,
    );

/**
 * Formats the first 32 hexadecimal characters of a transcript hash as a
 * session fingerprint for out-of-band comparison.
 *
 * @param transcriptHash Lowercase hexadecimal transcript hash.
 * @returns Grouped session fingerprint string.
 */
export const formatSessionFingerprint = (transcriptHash: string): string =>
    transcriptHash
        .slice(0, 32)
        .toUpperCase()
        .match(/.{1,4}/g)
        ?.join('-') ?? '';
