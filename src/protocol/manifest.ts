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
 * Validates the supported election-manifest invariants for the shipped
 * score-voting workflow.
 *
 * @param manifest Election manifest to validate.
 */
export const validateElectionManifest = (
    manifest: ElectionManifest,
): ElectionManifest => {
    assertNonEmptyString(manifest.protocolVersion, 'Protocol version');
    assertNonEmptyString(manifest.rosterHash, 'Roster hash');
    getGroup(manifest.suiteId);
    assertMajorityThreshold(manifest.threshold, manifest.participantCount);

    if (manifest.ballotFinality !== 'first-valid') {
        throw new InvalidPayloadError(
            'Only "first-valid" ballot finality is supported',
        );
    }

    if (
        !Number.isInteger(manifest.minimumPublicationThreshold) ||
        manifest.minimumPublicationThreshold < manifest.threshold + 1 ||
        manifest.minimumPublicationThreshold > manifest.participantCount
    ) {
        throw new InvalidPayloadError(
            `Minimum publication threshold must be an integer in ${manifest.threshold + 1}..${manifest.participantCount}`,
        );
    }

    if (
        !Number.isInteger(manifest.scoreDomainMin) ||
        !Number.isInteger(manifest.scoreDomainMax)
    ) {
        throw new InvalidPayloadError('Score domain bounds must be integers');
    }

    if (manifest.allowAbstention && manifest.scoreDomainMin !== 0) {
        throw new InvalidPayloadError(
            'Allowing abstention requires scoreDomainMin = 0',
        );
    }

    if (!manifest.allowAbstention && manifest.scoreDomainMin < 1) {
        throw new InvalidPayloadError(
            'Score voting without abstention requires scoreDomainMin >= 1',
        );
    }

    if (manifest.scoreDomainMax < manifest.scoreDomainMin) {
        throw new InvalidPayloadError(
            'scoreDomainMax must be greater than or equal to scoreDomainMin',
        );
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
