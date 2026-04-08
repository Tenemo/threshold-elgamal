import { bytesToHex } from '../core/bytes.js';
import { sha256, utf8ToBytes } from '../core/index.js';

import { canonicalizeJson } from './canonical-json.js';
import { sortProtocolPayloads } from './ordering.js';
import type { ProtocolPayload } from './types.js';

/**
 * Canonically serializes the ordered unsigned payload set for a transcript.
 *
 * @param payloads Payloads to include in the transcript.
 * @param bigintByteLength Fixed byte width used for any bigint fields.
 * @returns Canonical transcript bytes.
 */
export const canonicalTranscriptBytes = (
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
