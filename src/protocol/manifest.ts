import { bytesToHex } from '../core/bytes.js';
import { sha256, utf8ToBytes } from '../core/index.js';

import { canonicalizeJson } from './canonical-json.js';
import type { ElectionManifest } from './types.js';

/**
 * Canonically serializes an election manifest.
 *
 * @param manifest Election manifest to serialize.
 * @returns Canonical JSON text for the manifest.
 */
export const canonicalizeElectionManifest = (
    manifest: ElectionManifest,
): string => canonicalizeJson(manifest);

/**
 * Hashes a canonical election manifest with SHA-256.
 *
 * @param manifest Election manifest to hash.
 * @returns Lowercase hexadecimal SHA-256 digest.
 */
export const hashElectionManifest = async (
    manifest: ElectionManifest,
): Promise<string> =>
    bytesToHex(
        await sha256(utf8ToBytes(canonicalizeElectionManifest(manifest))),
    );

/**
 * Derives a globally unique session identifier from the frozen setup values.
 *
 * @param manifestHash Canonical manifest hash.
 * @param rosterHash Canonical roster hash.
 * @param randomNonce Public random nonce.
 * @param timestamp Timestamp string included in the derivation.
 * @returns Lowercase hexadecimal SHA-256 digest.
 */
export const deriveSessionId = async (
    manifestHash: string,
    rosterHash: string,
    randomNonce: string,
    timestamp: string,
): Promise<string> =>
    bytesToHex(
        await sha256(
            utf8ToBytes(
                [manifestHash, rosterHash, randomNonce, timestamp].join(':'),
            ),
        ),
    );
