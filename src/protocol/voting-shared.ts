import {
    assertPositiveParticipantIndex,
    InvalidPayloadError,
    RISTRETTO_GROUP,
} from '../core/index.js';
import type { ProofContext } from '../proofs/types.js';
import {
    importAuthPublicKey,
    verifyPayloadSignature,
} from '../transport/auth.js';

import {
    hashElectionManifest,
    SHIPPED_PROTOCOL_VERSION,
    validateElectionManifest,
} from './manifest.js';
import { canonicalUnsignedPayloadBytes } from './payloads.js';
import type {
    DecryptionSharePayload,
    ElectionManifest,
    ProtocolPayload,
    RegistrationPayload,
    SignedPayload,
    OptionAggregateInput,
} from './types.js';
import { scoreVotingDomain } from './voting-codecs.js';

export const BALLOT_SUBMISSION_PHASE = 5;
export const BALLOT_CLOSE_PHASE = 6;
export const DECRYPTION_SHARE_PHASE = 7;
export const TALLY_PUBLICATION_PHASE = 8;

type VotingManifestContext = {
    readonly manifest: ElectionManifest;
    readonly manifestHash: string;
    readonly optionCount: number;
    readonly protocolVersion: string;
    readonly scoreDomainValues: readonly bigint[];
    readonly sessionId: string;
};

export const assertPhase = (
    payload: ProtocolPayload,
    expectedPhase: number,
    label: string,
): void => {
    if (payload.phase !== expectedPhase) {
        throw new InvalidPayloadError(
            `${label} payload phase must equal ${expectedPhase}`,
        );
    }
};

export const assertNonEmptyString = (value: string, label: string): void => {
    if (value.trim() === '') {
        throw new InvalidPayloadError(`${label} must be a non-empty string`);
    }
};

export const assertUniqueSortedIndices = (
    indices: readonly number[],
    label: string,
): void => {
    let previous = 0;
    const seen = new Set<number>();

    for (const index of indices) {
        assertPositiveParticipantIndex(index);
        if (seen.has(index)) {
            throw new InvalidPayloadError(`${label} indices must be unique`);
        }
        if (index <= previous) {
            throw new InvalidPayloadError(
                `${label} indices must be strictly increasing`,
            );
        }
        seen.add(index);
        previous = index;
    }
};

export const assertValidOptionIndex = (
    optionIndex: number,
    optionCount: number,
    label: string,
): void => {
    if (!Number.isInteger(optionIndex) || optionIndex < 1) {
        throw new InvalidPayloadError(
            `${label} option index must be a positive integer`,
        );
    }

    if (optionIndex > optionCount) {
        throw new InvalidPayloadError(
            `${label} option index ${optionIndex} exceeds the manifest option count ${optionCount}`,
        );
    }
};

export const buildVotingManifestContext = async (
    manifest: ElectionManifest,
    sessionId: string,
): Promise<VotingManifestContext> => {
    const validatedManifest = validateElectionManifest(manifest);

    return {
        manifest: validatedManifest,
        manifestHash: await hashElectionManifest(validatedManifest),
        optionCount: validatedManifest.optionList.length,
        protocolVersion: SHIPPED_PROTOCOL_VERSION,
        scoreDomainValues: scoreVotingDomain(),
        sessionId,
    };
};

export const verifyPayloadsAgainstRegistrations = async (
    payloads: readonly SignedPayload[],
    registrations: readonly SignedPayload<RegistrationPayload>[],
): Promise<void> => {
    const authKeyMap = new Map<number, CryptoKey>();

    for (const registration of registrations) {
        authKeyMap.set(
            registration.payload.participantIndex,
            await importAuthPublicKey(registration.payload.authPublicKey),
        );
    }

    for (const payload of payloads) {
        const publicKey = authKeyMap.get(payload.payload.participantIndex);
        if (publicKey === undefined) {
            throw new InvalidPayloadError(
                `Missing registration for participant ${payload.payload.participantIndex}`,
            );
        }

        const valid = await verifyPayloadSignature(
            publicKey,
            canonicalUnsignedPayloadBytes(payload.payload),
            payload.signature,
        );
        if (!valid) {
            throw new InvalidPayloadError(
                `Payload signature failed verification for participant ${payload.payload.participantIndex} (${payload.payload.messageType})`,
            );
        }
    }
};

export const buildOptionAggregateMap = (
    aggregates: readonly OptionAggregateInput[],
    optionCount: number,
): ReadonlyMap<number, OptionAggregateInput> => {
    const aggregateMap = new Map<number, OptionAggregateInput>();

    for (const aggregate of aggregates) {
        assertValidOptionIndex(aggregate.optionIndex, optionCount, 'Aggregate');
        if (aggregateMap.has(aggregate.optionIndex)) {
            throw new InvalidPayloadError(
                `Duplicate aggregate for option ${aggregate.optionIndex} is not allowed`,
            );
        }
        aggregateMap.set(aggregate.optionIndex, aggregate);
    }

    for (let optionIndex = 1; optionIndex <= optionCount; optionIndex += 1) {
        if (!aggregateMap.has(optionIndex)) {
            throw new InvalidPayloadError(
                `Missing verified aggregate for option ${optionIndex}`,
            );
        }
    }

    return aggregateMap;
};

export const decryptionProofContext = (
    payload: DecryptionSharePayload,
    protocolVersion: string,
): ProofContext => ({
    protocolVersion,
    suiteId: RISTRETTO_GROUP.name,
    manifestHash: payload.manifestHash,
    sessionId: payload.sessionId,
    label: 'decryption-share-dleq',
    participantIndex: payload.participantIndex,
    optionIndex: payload.optionIndex,
});

export const sameNumberSet = (
    left: readonly number[],
    right: readonly number[],
): boolean =>
    left.length === right.length &&
    left.every((value, index) => value === right[index]);
