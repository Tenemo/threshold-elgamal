import { bytesToHex } from '../core/bytes.js';
import {
    InvalidPayloadError,
    assertMajorityThreshold,
    getGroup,
    sha256,
    utf8ToBytes,
} from '../core/index.js';
import { encodeForChallenge } from '../serialize/index.js';

import { canonicalizeJson } from './canonical-json.js';
import type { ElectionManifest } from './types.js';

const assertNonEmptyString = (value: string, label: string): void => {
    if (value.trim() === '') {
        throw new InvalidPayloadError(`${label} must be a non-empty string`);
    }
};

/**
 * Returns the minimum publication floor compatible with the shipped
 * strict-majority threshold policy.
 *
 * The manifest threshold is the reconstruction threshold `k = t + 1`, so the
 * small-group privacy floor `t + 2` becomes `k + 1`.
 *
 * @param reconstructionThreshold Reconstruction threshold `k`.
 * @param participantCount Total participant count `n`.
 * @returns Minimum accepted ballot count `k + 1`.
 */
export const defaultMinimumPublishedVoterCount = (
    reconstructionThreshold: number,
    participantCount: number,
): number =>
    assertMajorityThreshold(reconstructionThreshold, participantCount) + 1;

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

    assertNonEmptyString(manifest.protocolVersion, 'Protocol version');
    assertNonEmptyString(manifest.rosterHash, 'Roster hash');
    getGroup(manifest.suiteId);
    assertMajorityThreshold(
        manifest.reconstructionThreshold,
        manifest.participantCount,
    );

    if (manifest.ballotFinality !== 'first-valid') {
        throw new InvalidPayloadError(
            'Only "first-valid" ballot finality is supported',
        );
    }

    if (
        !Number.isInteger(manifest.minimumPublishedVoterCount) ||
        manifest.minimumPublishedVoterCount <
            defaultMinimumPublishedVoterCount(
                manifest.reconstructionThreshold,
                manifest.participantCount,
            ) ||
        manifest.minimumPublishedVoterCount > manifest.participantCount
    ) {
        throw new InvalidPayloadError(
            `Minimum published voter count must be an integer in ${defaultMinimumPublishedVoterCount(
                manifest.reconstructionThreshold,
                manifest.participantCount,
            )}..${manifest.participantCount}`,
        );
    }

    for (const legacyField of [
        'threshold',
        'minimumPublicationThreshold',
        'allowAbstention',
        'scoreDomainMin',
        'scoreDomainMax',
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

    if (manifest.epochDeadlines.length === 0) {
        throw new InvalidPayloadError(
            'Election manifest requires at least one epoch deadline',
        );
    }

    const seenDeadlines = new Set<string>();
    let previousDeadline = '';
    for (const deadline of manifest.epochDeadlines) {
        assertNonEmptyString(deadline, 'Epoch deadline');
        if (seenDeadlines.has(deadline)) {
            throw new InvalidPayloadError(
                `Duplicate epoch deadline "${deadline}" is not allowed`,
            );
        }
        if (previousDeadline !== '' && deadline <= previousDeadline) {
            throw new InvalidPayloadError(
                'Epoch deadlines must be strictly increasing',
            );
        }
        seenDeadlines.add(deadline);
        previousDeadline = deadline;
    }

    return manifest;
};

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
