/**
 * Manifest validation, hashing, and session-derivation helpers.
 *
 * This is the entry point for freezing the ceremony root that every later DKG,
 * ballot, decryption-share, and tally payload binds to.
 */
import { bytesToHex } from '../core/bytes';
import { InvalidPayloadError, sha256, utf8ToBytes } from '../core/index';
import { encodeForChallenge } from '../serialize/encoding';

import { canonicalizeJson } from './canonical-json';
import type { ElectionManifest } from './types';

/**
 * Default protocol namespace used by the built-in helpers and verifier.
 *
 * The current verifier only accepts this namespace, so applications that want
 * verifier-compatible payloads should treat this value as fixed.
 */
export const SHIPPED_PROTOCOL_VERSION = 'v1';

const assertNonEmptyString = (value: string, label: string): void => {
    if (value.trim() === '') {
        throw new InvalidPayloadError(`${label} must be a non-empty string`);
    }
};

/**
 * Validates that a protocol version string is present and non-empty.
 *
 * Builders use this to normalize explicit overrides before attaching them to
 * published payloads.
 */
export const assertValidProtocolVersion = (
    protocolVersion: string,
    label = 'Protocol version',
): string => {
    assertNonEmptyString(protocolVersion, label);

    return protocolVersion;
};

/**
 * Validates that a protocol version matches the verifier namespace.
 *
 * Verifier-facing paths call this when they need to reject protocol variants
 * that are outside the package's supported public workflow.
 */
export const assertSupportedProtocolVersion = (
    protocolVersion: string,
    label = 'Protocol version',
): string => {
    assertValidProtocolVersion(protocolVersion, label);

    if (protocolVersion !== SHIPPED_PROTOCOL_VERSION) {
        throw new InvalidPayloadError(
            `${label} must equal ${SHIPPED_PROTOCOL_VERSION}`,
        );
    }

    return protocolVersion;
};

/**
 * Validates the supported election-manifest invariants for the score-voting
 * workflow.
 *
 * The manifest is intentionally minimal: it fixes the frozen roster hash and
 * option list, while participant count and threshold are derived later from the
 * accepted registration roster.
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

/**
 * Creates the minimal election manifest after validating the supported
 * invariants.
 */
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
 * The resulting digest is the manifest anchor reused by every later payload,
 * proof context, and verifier stage.
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
 * Applications normally compute this once after freezing the manifest and
 * roster so every later payload can bind itself to one concrete ceremony
 * instance.
 */
export const deriveSessionId = async (
    manifestHash: string,
    rosterHash: string,
    randomNonce: string,
    timestamp: string,
    protocolVersion?: string,
): Promise<string> =>
    bytesToHex(
        await sha256(
            encodeForChallenge(
                assertValidProtocolVersion(
                    protocolVersion ?? SHIPPED_PROTOCOL_VERSION,
                    'Session protocol version',
                ),
                manifestHash,
                rosterHash,
                randomNonce,
                timestamp,
            ),
        ),
    );
