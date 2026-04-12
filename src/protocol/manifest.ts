import { bytesToHex } from '../core/bytes';
import { InvalidPayloadError, sha256, utf8ToBytes } from '../core/index';
import { encodeForChallenge } from '../serialize/index';

import { canonicalizeJson } from './canonical-json';
import type { ElectionManifest } from './types';

/** Fixed transcript version string for the shipped beta protocol. */
export const SHIPPED_PROTOCOL_VERSION = 'v1';

const assertNonEmptyString = (value: string, label: string): void => {
    if (value.trim() === '') {
        throw new InvalidPayloadError(`${label} must be a non-empty string`);
    }
};

/**
 * Validates the supported election-manifest invariants for the shipped
 * score-voting workflow.
 *
 * @param manifest Election manifest to validate.
 */
export const validateElectionManifest = (
    manifest: ElectionManifest,
): ElectionManifest => {
    const manifestRecord = manifest as Record<string, unknown>;
    assertNonEmptyString(manifest.rosterHash, 'Roster hash');

    for (const legacyField of [
        'participantCount',
        'reconstructionThreshold',
        'minimumPublishedVoterCount',
        'protocolVersion',
        'ballotCompletenessPolicy',
        'ballotFinality',
        'scoreDomain',
        'epochDeadlines',
        'threshold',
        'minimumPublicationThreshold',
        'allowAbstention',
        'scoreDomainMin',
        'scoreDomainMax',
        'requiresAllOptions',
    ]) {
        if (legacyField in manifestRecord) {
            throw new InvalidPayloadError(
                `Legacy manifest field "${legacyField}" is not supported on the Ristretto beta line`,
            );
        }
    }

    if (manifest.optionList.length === 0) {
        throw new InvalidPayloadError(
            'Election manifest requires at least one option',
        );
    }

    const seenOptions = new Set<string>();
    for (const option of manifest.optionList) {
        assertNonEmptyString(option, 'Option');
        if (seenOptions.has(option)) {
            throw new InvalidPayloadError(
                `Duplicate option "${option}" is not allowed`,
            );
        }
        seenOptions.add(option);
    }

    return manifest;
};

/** Creates the minimal shipped election manifest. */
export const createElectionManifest = (
    manifest: ElectionManifest,
): ElectionManifest => validateElectionManifest(manifest);

/**
 * Canonically serializes an election manifest.
 *
 * @param manifest Election manifest to serialize.
 * @returns Canonical JSON text for the manifest.
 */
export const canonicalizeElectionManifest = (
    manifest: ElectionManifest,
): string => canonicalizeJson(validateElectionManifest(manifest));

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
            encodeForChallenge(
                manifestHash,
                rosterHash,
                randomNonce,
                timestamp,
            ),
        ),
    );
