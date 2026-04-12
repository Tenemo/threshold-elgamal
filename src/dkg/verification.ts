import {
    InvalidPayloadError,
    RISTRETTO_GROUP,
    ThresholdViolationError,
    assertCanonicalRistrettoGroup,
    assertInSubgroupOrIdentity,
    assertPositiveParticipantIndex,
    majorityThreshold,
    modQ,
    type CryptoGroup,
} from '../core/index';
import {
    RISTRETTO_ZERO,
    decodePoint,
    decodeScalar,
    encodePoint,
    pointAdd,
    pointMultiply,
} from '../core/ristretto';
import type { EncodedPoint } from '../core/types';
import type { ProofContext } from '../proofs/index';
import { verifySchnorrProof } from '../proofs/index';
import { auditSignedPayloads } from '../protocol/board-audit';
import {
    hashElectionManifest,
    SHIPPED_PROTOCOL_VERSION,
} from '../protocol/manifest';
import { hashProtocolTranscript } from '../protocol/transcript';
import type {
    ComplaintPayload,
    ElectionManifest,
    EncryptedDualSharePayload,
    FeldmanCommitmentPayload,
    KeyDerivationConfirmation,
    ManifestAcceptancePayload,
    ManifestPublicationPayload,
    PhaseCheckpointPayload,
    ProtocolMessageType,
    RegistrationPayload,
    SignedPayload,
} from '../protocol/types';
import {
    verifySignedProtocolPayloads,
    type VerifiedProtocolSignatures,
} from '../protocol/verification';

import {
    assertSupportedCheckpointPayloads,
    isPhaseCheckpointPayload,
    resolveVerifiedPhaseCheckpoint,
    type FinalizedPhaseCheckpoint,
} from './checkpoints';
import {
    assertEncryptedShareCoverage,
    assertPedersenCommitmentCoverage,
    buildEncryptedShareMatrix,
    parsePedersenCommitmentMap,
    verifyComplaintOutcomes,
} from './verification-complaints';

/** Input bundle for verifying a DKG transcript. */
export type VerifyDKGTranscriptInput = {
    readonly transcript: readonly SignedPayload[];
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
};

/** Verified DKG transcript result with reusable derived ceremony material. */
export type VerifiedDKGTranscript = {
    readonly acceptedComplaints: readonly ComplaintPayload[];
    readonly jointPublicKey: EncodedPoint;
    readonly feldmanCommitments: readonly {
        readonly dealerIndex: number;
        readonly commitments: readonly EncodedPoint[];
    }[];
    readonly manifestAccepted: readonly number[];
    readonly organizerIndex: number;
    readonly participantCount: number;
    readonly phaseCheckpoints: readonly FinalizedPhaseCheckpoint[];
    readonly qualifiedParticipantIndices: readonly number[];
    readonly dkgTranscriptHash: string;
    readonly registrations: readonly SignedPayload<RegistrationPayload>[];
    readonly rosterHash: string;
    readonly threshold: number;
};

export type EncryptedShareMatrix = {
    readonly encryptedShares: readonly SignedPayload<EncryptedDualSharePayload>[];
    readonly bySlot: ReadonlyMap<
        string,
        SignedPayload<EncryptedDualSharePayload>
    >;
    readonly byComplaintKey: ReadonlyMap<
        string,
        SignedPayload<EncryptedDualSharePayload>
    >;
};

type ParsedFeldmanCommitment = {
    readonly dealerIndex: number;
    readonly commitments: readonly EncodedPoint[];
    readonly payload: FeldmanCommitmentPayload;
};

export type ResolvePhaseCheckpointInput = {
    readonly transcript: readonly SignedPayload[];
    readonly checkpointPhase: number;
    readonly threshold: number;
    readonly participantCount: number;
    readonly expectedQualifiedParticipantIndices: readonly number[];
    readonly signerUniverse: ReadonlySet<number>;
};

type VerifiedDKGSetup = {
    readonly manifestAccepted: readonly number[];
    readonly manifestPublication: ManifestPublicationPayload;
    readonly participantIndices: readonly number[];
    readonly threshold: number;
    readonly verifiedSignatures: VerifiedProtocolSignatures;
};

const GJKR_PHASE_PLAN: Readonly<Record<ProtocolMessageType, number | null>> = {
    'manifest-publication': 0,
    registration: 0,
    'manifest-acceptance': 0,
    'phase-checkpoint': null,
    'pedersen-commitment': 1,
    'encrypted-dual-share': 1,
    complaint: 2,
    'complaint-resolution': 2,
    'feldman-commitment': 3,
    'key-derivation-confirmation': 4,
    'ballot-submission': null,
    'ballot-close': null,
    'decryption-share': null,
    'tally-publication': null,
};

const expectedDKGPhase = (
    messageType: ProtocolMessageType,
    payload?: PhaseCheckpointPayload,
): number | null =>
    messageType === 'phase-checkpoint'
        ? (payload?.checkpointPhase ?? null)
        : GJKR_PHASE_PLAN[messageType];

const groupByParticipant = <
    TPayload extends { readonly participantIndex: number },
>(
    payloads: readonly TPayload[],
): Map<number, TPayload[]> => {
    const map = new Map<number, TPayload[]>();
    for (const payload of payloads) {
        const existing = map.get(payload.participantIndex) ?? [];
        existing.push(payload);
        map.set(payload.participantIndex, existing);
    }
    return map;
};

const requireExactlyOnePayload = <TPayload>(
    payloads: readonly TPayload[],
    label: string,
): TPayload => {
    if (payloads.length !== 1) {
        throw new InvalidPayloadError(`${label} requires exactly one payload`);
    }

    return payloads[0];
};

export const parseCommitmentVector = (
    commitments: readonly string[],
    expectedLength: number,
    label: string,
): readonly EncodedPoint[] => {
    if (commitments.length !== expectedLength) {
        throw new InvalidPayloadError(
            `${label} must contain exactly ${expectedLength} commitments`,
        );
    }

    const parsed = commitments.map((commitment) => {
        assertInSubgroupOrIdentity(commitment);
        return commitment as EncodedPoint;
    });
    if (
        decodePoint(parsed[parsed.length - 1], `${label} last commitment`).is0()
    ) {
        throw new InvalidPayloadError(
            `${label} must commit to the exact claimed polynomial degree`,
        );
    }

    return parsed;
};

const buildSchnorrContext = (
    payload: FeldmanCommitmentPayload,
    protocolVersion: string,
    coefficientIndex: number,
): ProofContext => ({
    protocolVersion,
    suiteId: RISTRETTO_GROUP.name,
    manifestHash: payload.manifestHash,
    sessionId: payload.sessionId,
    label: 'feldman-coefficient-proof',
    participantIndex: payload.participantIndex,
    coefficientIndex,
});

export const complaintResolutionKey = (
    complainantIndex: number,
    dealerIndex: number,
    envelopeId: string,
): string => `${complainantIndex}:${dealerIndex}:${envelopeId}`;

export const encryptedShareSlotKey = (
    dealerIndex: number,
    recipientIndex: number,
): string => `${dealerIndex}:${recipientIndex}`;

const allParticipantIndices = (participantCount: number): readonly number[] =>
    Array.from({ length: participantCount }, (_value, index) => index + 1);

export const validateParticipantIndex = (
    index: number,
    participantCount: number,
    label: string,
): void => {
    if (!Number.isInteger(index) || index < 1 || index > participantCount) {
        throw new InvalidPayloadError(
            `${label} ${index} must satisfy 1 <= j <= n (n = ${participantCount})`,
        );
    }
};

export const assertUniqueSortedParticipantIndices = (
    indices: readonly number[],
    participantCount: number,
    label: string,
): void => {
    let previous = 0;
    const seen = new Set<number>();

    for (const index of indices) {
        validateParticipantIndex(index, participantCount, label);
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

const validateTranscriptShape = (
    input: VerifyDKGTranscriptInput,
    manifestHash: string,
): void => {
    for (const signedPayload of input.transcript) {
        const expected = expectedDKGPhase(
            signedPayload.payload.messageType,
            isPhaseCheckpointPayload(signedPayload)
                ? signedPayload.payload
                : undefined,
        );
        if (expected === null || signedPayload.payload.phase !== expected) {
            throw new InvalidPayloadError(
                'Payload phase does not match the GJKR phase plan',
            );
        }
        if (signedPayload.payload.sessionId !== input.sessionId) {
            throw new InvalidPayloadError(
                'Payload session does not match the verification input',
            );
        }
        if (signedPayload.payload.manifestHash !== manifestHash) {
            throw new InvalidPayloadError(
                'Payload manifest hash does not match the verification input',
            );
        }
    }
};

export const assertIndexSubset = (
    indices: readonly number[],
    allowed: ReadonlySet<number>,
    label: string,
): void => {
    for (const index of indices) {
        if (!allowed.has(index)) {
            throw new InvalidPayloadError(
                `${label} ${index} is not part of the allowed participant set`,
            );
        }
    }
};

const deriveTranscriptVerificationKeyInternal = (
    commitmentSets: readonly (readonly EncodedPoint[])[],
    participantIndex: number,
    group: CryptoGroup,
): EncodedPoint => {
    assertCanonicalRistrettoGroup(
        group,
        'Transcript verification-key derivation group',
    );
    assertPositiveParticipantIndex(participantIndex);
    const point = BigInt(participantIndex);

    return encodePoint(
        commitmentSets.reduce((outerAccumulator, commitments) => {
            let innerAccumulator = RISTRETTO_ZERO;
            let exponent = 1n;

            for (const commitment of commitments) {
                innerAccumulator = pointAdd(
                    innerAccumulator,
                    pointMultiply(
                        decodePoint(commitment, 'Feldman commitment'),
                        exponent,
                    ),
                );
                exponent = modQ(exponent * point, group.q);
            }

            return pointAdd(outerAccumulator, innerAccumulator);
        }, RISTRETTO_ZERO),
    );
};

/**
 * Derives the transcript verification key `Y_j` for one participant index from
 * published Feldman commitments.
 *
 * @param feldmanCommitments Qualified dealer commitment vectors.
 * @param participantIndex Participant index whose key will be derived.
 * @param group Selected group.
 * @returns Transcript-derived verification key `Y_j`.
 */
export const deriveTranscriptVerificationKey = (
    feldmanCommitments: readonly {
        readonly dealerIndex: number;
        readonly commitments: readonly EncodedPoint[];
    }[],
    participantIndex: number,
    group: CryptoGroup,
): EncodedPoint =>
    deriveTranscriptVerificationKeyInternal(
        feldmanCommitments.map((entry) => entry.commitments),
        participantIndex,
        group,
    );

/**
 * Derives the qualified joint public key from the constant Feldman
 * commitments.
 *
 * @param feldmanCommitments Qualified dealer commitment vectors.
 * @param group Selected group.
 * @returns Derived joint public key.
 */
export const deriveJointPublicKey = (
    feldmanCommitments: readonly {
        readonly dealerIndex: number;
        readonly commitments: readonly EncodedPoint[];
    }[],
    group: CryptoGroup,
): EncodedPoint => {
    assertCanonicalRistrettoGroup(group, 'Joint public-key derivation group');

    return encodePoint(
        feldmanCommitments.reduce(
            (sum, entry) =>
                pointAdd(
                    sum,
                    decodePoint(entry.commitments[0], 'Constant commitment'),
                ),
            RISTRETTO_ZERO,
        ),
    );
};

/**
 * Derives the qualified participant set from accepted complaint outcomes.
 *
 * @param participantCount Total participant count.
 * @param acceptedComplaints Complaint set resolved in the dealer-fault branch.
 * @returns Qualified participant indices.
 */
const deriveQualifiedParticipantIndices = (
    participantCount: number,
    acceptedComplaints: readonly ComplaintPayload[],
): readonly number[] => {
    const disqualifiedDealers = new Set(
        acceptedComplaints.map((complaint) => complaint.dealerIndex),
    );

    return Array.from(
        { length: participantCount },
        (_value, index) => index + 1,
    ).filter((index) => !disqualifiedDealers.has(index));
};

const verifySignedRoster = async (
    transcript: readonly SignedPayload[],
    expectedRosterHash: string,
): Promise<VerifiedProtocolSignatures> => {
    const verifiedSignatures = await verifySignedProtocolPayloads(transcript);
    if (verifiedSignatures.rosterHash !== expectedRosterHash) {
        throw new InvalidPayloadError(
            'Registration roster hash does not match the manifest roster hash',
        );
    }

    return verifiedSignatures;
};

const verifyManifestPublicationPayload = async (
    transcript: readonly SignedPayload[],
    manifestHash: string,
): Promise<ManifestPublicationPayload> => {
    const manifestPublication = requireExactlyOnePayload(
        transcript
            .filter(
                (
                    payload,
                ): payload is SignedPayload<ManifestPublicationPayload> =>
                    payload.payload.messageType === 'manifest-publication',
            )
            .map((payload) => payload.payload),
        'Manifest publication',
    );
    if (
        (await hashElectionManifest(manifestPublication.manifest)) !==
        manifestHash
    ) {
        throw new InvalidPayloadError(
            'Manifest publication does not match the verification input manifest',
        );
    }

    return manifestPublication;
};

const verifyManifestAcceptancePayloads = (
    transcript: readonly SignedPayload[],
    allowedParticipantIndices: readonly number[],
    expectedRosterHash: string,
    requireUnanimous: boolean,
): readonly number[] => {
    const acceptances = transcript
        .filter(
            (payload): payload is SignedPayload<ManifestAcceptancePayload> =>
                payload.payload.messageType === 'manifest-acceptance',
        )
        .map((payload) => payload.payload);
    const grouped = groupByParticipant(acceptances);
    const participantCount = allowedParticipantIndices.length;
    const allowedParticipantSet = new Set(allowedParticipantIndices);

    if (requireUnanimous && grouped.size !== participantCount) {
        throw new InvalidPayloadError(
            `Manifest acceptance requires exactly ${participantCount} participant payloads`,
        );
    }

    for (const [participantIndex, participantPayloads] of grouped.entries()) {
        validateParticipantIndex(
            participantIndex,
            participantCount,
            'Manifest acceptance participant index',
        );
        if (!allowedParticipantSet.has(participantIndex)) {
            throw new InvalidPayloadError(
                `Manifest acceptance participant ${participantIndex} is not part of the frozen registration roster`,
            );
        }
        if (participantPayloads.length !== 1) {
            throw new InvalidPayloadError(
                `Manifest acceptance requires exactly one payload for participant ${participantIndex}`,
            );
        }
    }

    for (const acceptance of acceptances) {
        if (acceptance.rosterHash !== expectedRosterHash) {
            throw new InvalidPayloadError(
                `Manifest acceptance roster hash mismatch for participant ${acceptance.participantIndex}`,
            );
        }
        if (
            acceptance.assignedParticipantIndex !== acceptance.participantIndex
        ) {
            throw new InvalidPayloadError(
                `Participant ${acceptance.participantIndex} accepted a mismatched assigned index`,
            );
        }
    }

    const acceptedParticipantIndices = acceptances
        .map((acceptance) => acceptance.participantIndex)
        .sort((left, right) => left - right);

    if (requireUnanimous) {
        for (const participantIndex of allowedParticipantIndices) {
            if (!grouped.has(participantIndex)) {
                throw new InvalidPayloadError(
                    `Manifest acceptance requires a payload for registered participant ${participantIndex}`,
                );
            }
        }
    }

    return acceptedParticipantIndices;
};

const parseQualifiedFeldmanCommitments = (
    transcript: readonly SignedPayload[],
    qualifiedParticipantIndices: readonly number[],
    threshold: number,
): readonly ParsedFeldmanCommitment[] => {
    const feldmanPayloads = transcript.filter(
        (payload): payload is SignedPayload<FeldmanCommitmentPayload> =>
            payload.payload.messageType === 'feldman-commitment',
    );

    return qualifiedParticipantIndices.map((participantIndex) => {
        const payload = feldmanPayloads.find(
            (candidate) =>
                candidate.payload.participantIndex === participantIndex,
        );
        if (payload === undefined) {
            throw new InvalidPayloadError(
                `Missing Feldman commitment payload for qualified dealer ${participantIndex}`,
            );
        }

        const commitments = parseCommitmentVector(
            payload.payload.commitments,
            threshold,
            'Feldman commitment payload',
        );

        if (payload.payload.proofs.length !== commitments.length) {
            throw new InvalidPayloadError(
                `Feldman commitment payload for participant ${participantIndex} must carry one proof per coefficient`,
            );
        }

        const seenCoefficientIndices = new Set<number>();
        commitments.forEach((_commitment, offset) => {
            const proofRecord = payload.payload.proofs[offset];
            if (proofRecord.coefficientIndex !== offset + 1) {
                throw new InvalidPayloadError(
                    `Feldman proof order mismatch for participant ${participantIndex}`,
                );
            }
            if (seenCoefficientIndices.has(proofRecord.coefficientIndex)) {
                throw new InvalidPayloadError(
                    `Duplicate Feldman proof index ${proofRecord.coefficientIndex} for participant ${participantIndex}`,
                );
            }
            seenCoefficientIndices.add(proofRecord.coefficientIndex);
        });

        return {
            dealerIndex: participantIndex,
            commitments,
            payload: payload.payload,
        };
    });
};

const verifyFeldmanProofs = async (
    feldmanCommitments: readonly ParsedFeldmanCommitment[],
    protocolVersion: string,
    group: CryptoGroup,
): Promise<void> => {
    for (const entry of feldmanCommitments) {
        for (const [offset, commitment] of entry.commitments.entries()) {
            const proof = entry.payload.proofs[offset];
            const valid = await verifySchnorrProof(
                {
                    challenge: decodeScalar(
                        proof.challenge,
                        'Schnorr challenge',
                    ),
                    response: decodeScalar(proof.response, 'Schnorr response'),
                },
                commitment,
                group,
                buildSchnorrContext(entry.payload, protocolVersion, offset + 1),
            );
            if (!valid) {
                throw new InvalidPayloadError(
                    `Feldman Schnorr proof failed verification for participant ${entry.dealerIndex} coefficient ${offset + 1}`,
                );
            }
        }
    }
};

const assertAggregateFeldmanDegree = (
    feldmanCommitments: readonly ParsedFeldmanCommitment[],
): void => {
    const aggregateHighestDegreeCommitment = feldmanCommitments.reduce(
        (sum, entry) =>
            pointAdd(
                sum,
                decodePoint(
                    entry.commitments[entry.commitments.length - 1],
                    'Qualified Feldman highest-degree commitment',
                ),
            ),
        RISTRETTO_ZERO,
    );

    if (aggregateHighestDegreeCommitment.is0()) {
        throw new InvalidPayloadError(
            'Qualified Feldman commitments collapse below the claimed reconstruction threshold',
        );
    }
};

const verifyKeyDerivationConfirmations = async (
    transcript: readonly SignedPayload[],
    qualifiedParticipantIndices: readonly number[],
    jointPublicKey: EncodedPoint,
    group: CryptoGroup,
    minimumConfirmations = qualifiedParticipantIndices.length,
): Promise<string> => {
    const qualifiedParticipantSet = new Set(qualifiedParticipantIndices);
    const preConfirmationTranscript = transcript.filter(
        (payload) =>
            payload.payload.messageType !== 'key-derivation-confirmation',
    );
    const dkgTranscriptHash = await hashProtocolTranscript(
        preConfirmationTranscript.map((payload) => payload.payload),
        group.byteLength,
    );
    const confirmations = transcript.filter(
        (payload): payload is SignedPayload<KeyDerivationConfirmation> =>
            payload.payload.messageType === 'key-derivation-confirmation',
    );

    if (confirmations.length < minimumConfirmations) {
        throw new InvalidPayloadError(
            `Expected at least ${minimumConfirmations} key-derivation confirmations, received ${confirmations.length}`,
        );
    }

    const seenConfirmations = new Set<number>();
    for (const confirmation of confirmations) {
        if (
            !qualifiedParticipantSet.has(confirmation.payload.participantIndex)
        ) {
            throw new InvalidPayloadError(
                `Key-derivation confirmation came from non-qualified participant ${confirmation.payload.participantIndex}`,
            );
        }
        if (seenConfirmations.has(confirmation.payload.participantIndex)) {
            throw new InvalidPayloadError(
                `Duplicate key-derivation confirmation for participant ${confirmation.payload.participantIndex}`,
            );
        }
        seenConfirmations.add(confirmation.payload.participantIndex);

        if (confirmation.payload.dkgTranscriptHash !== dkgTranscriptHash) {
            throw new InvalidPayloadError(
                `DKG transcript hash mismatch in confirmation from participant ${confirmation.payload.participantIndex}`,
            );
        }
        if (confirmation.payload.publicKey !== jointPublicKey) {
            throw new InvalidPayloadError(
                `Joint public key mismatch in confirmation from participant ${confirmation.payload.participantIndex}`,
            );
        }
    }

    return dkgTranscriptHash;
};

const reduceQualifiedParticipantIndices = (
    qualifiedParticipantIndices: readonly number[],
    acceptedComplaints: readonly ComplaintPayload[],
): readonly number[] => {
    const disqualifiedDealers = new Set(
        acceptedComplaints.map((complaint) => complaint.dealerIndex),
    );

    return qualifiedParticipantIndices.filter(
        (participantIndex) => !disqualifiedDealers.has(participantIndex),
    );
};

const assertQualifiedThreshold = (
    qualifiedParticipantIndices: readonly number[],
    threshold: number,
): void => {
    if (qualifiedParticipantIndices.length < threshold) {
        throw new InvalidPayloadError(
            'The qualified participant set fell below the reconstruction threshold',
        );
    }
};

const normalizeFeldmanCommitments = (
    feldmanCommitments: readonly ParsedFeldmanCommitment[],
): readonly {
    readonly dealerIndex: number;
    readonly commitments: readonly EncodedPoint[];
}[] =>
    feldmanCommitments.map((entry) => ({
        dealerIndex: entry.dealerIndex,
        commitments: entry.commitments,
    }));

const buildVerifiedDKGSetup = async (
    input: VerifyDKGTranscriptInput,
    manifestHash: string,
): Promise<VerifiedDKGSetup> => {
    const verifiedSignatures = await verifySignedRoster(
        input.transcript,
        input.manifest.rosterHash,
    );

    if (verifiedSignatures.participantCount < 3) {
        throw new ThresholdViolationError(
            'Distributed threshold workflows require at least three participants',
        );
    }

    const manifestPublication = await verifyManifestPublicationPayload(
        input.transcript,
        manifestHash,
    );
    const participantIndices = allParticipantIndices(
        verifiedSignatures.participantCount,
    );
    const manifestAccepted = verifyManifestAcceptancePayloads(
        input.transcript,
        participantIndices,
        input.manifest.rosterHash,
        true,
    );

    return {
        manifestAccepted,
        manifestPublication,
        participantIndices,
        threshold: majorityThreshold(verifiedSignatures.participantCount),
        verifiedSignatures,
    };
};

const finalizeVerifiedTranscript = async (
    input: VerifyDKGTranscriptInput,
    verifiedSignatures: VerifiedProtocolSignatures,
    organizerIndex: number,
    acceptedComplaints: readonly ComplaintPayload[],
    manifestAccepted: readonly number[],
    phaseCheckpoints: readonly FinalizedPhaseCheckpoint[],
    qualifiedParticipantIndices: readonly number[],
    group: CryptoGroup,
    threshold: number,
): Promise<VerifiedDKGTranscript> => {
    assertQualifiedThreshold(qualifiedParticipantIndices, threshold);

    const feldmanCommitments = parseQualifiedFeldmanCommitments(
        input.transcript,
        qualifiedParticipantIndices,
        threshold,
    );
    await verifyFeldmanProofs(
        feldmanCommitments,
        SHIPPED_PROTOCOL_VERSION,
        group,
    );
    assertAggregateFeldmanDegree(feldmanCommitments);

    const normalizedFeldmanCommitments =
        normalizeFeldmanCommitments(feldmanCommitments);
    const jointPublicKey = deriveJointPublicKey(
        normalizedFeldmanCommitments,
        group,
    );
    if (decodePoint(jointPublicKey, 'Derived joint public key').is0()) {
        throw new InvalidPayloadError(
            'Derived joint public key must not be the identity element',
        );
    }
    const dkgTranscriptHash = await verifyKeyDerivationConfirmations(
        input.transcript,
        qualifiedParticipantIndices,
        jointPublicKey,
        group,
        qualifiedParticipantIndices.length,
    );

    return {
        acceptedComplaints,
        jointPublicKey,
        feldmanCommitments: normalizedFeldmanCommitments,
        manifestAccepted,
        organizerIndex,
        participantCount: verifiedSignatures.participantCount,
        phaseCheckpoints,
        qualifiedParticipantIndices,
        dkgTranscriptHash,
        registrations: verifiedSignatures.registrations,
        rosterHash: verifiedSignatures.rosterHash,
        threshold,
    };
};

const verifyLegacyDKGTranscript = async (
    input: VerifyDKGTranscriptInput,
    setup: VerifiedDKGSetup,
): Promise<VerifiedDKGTranscript> => {
    const encryptedShareMatrix = buildEncryptedShareMatrix(
        input.transcript,
        setup.verifiedSignatures.participantCount,
    );
    assertEncryptedShareCoverage(
        encryptedShareMatrix,
        setup.participantIndices,
    );

    const pedersenCommitmentMap = parsePedersenCommitmentMap(
        input.transcript,
        setup.threshold,
    );
    assertPedersenCommitmentCoverage(
        pedersenCommitmentMap,
        setup.participantIndices,
    );

    const acceptedComplaints = await verifyComplaintOutcomes(
        input,
        setup.verifiedSignatures,
        encryptedShareMatrix,
        pedersenCommitmentMap,
        RISTRETTO_GROUP,
        new Set(setup.participantIndices),
    );
    const qualifiedParticipantIndices = deriveQualifiedParticipantIndices(
        setup.verifiedSignatures.participantCount,
        acceptedComplaints,
    );

    return finalizeVerifiedTranscript(
        input,
        setup.verifiedSignatures,
        setup.manifestPublication.participantIndex,
        acceptedComplaints,
        setup.manifestAccepted,
        [],
        qualifiedParticipantIndices,
        RISTRETTO_GROUP,
        setup.threshold,
    );
};

const verifyCheckpointedDKGTranscript = async (
    input: VerifyDKGTranscriptInput,
    setup: VerifiedDKGSetup,
): Promise<VerifiedDKGTranscript> => {
    assertSupportedCheckpointPayloads(input.transcript);

    const manifestAcceptedSet = new Set(setup.manifestAccepted);

    const phase0Checkpoint = await resolveVerifiedPhaseCheckpoint({
        transcript: input.transcript,
        checkpointPhase: 0,
        threshold: setup.threshold,
        participantCount: setup.verifiedSignatures.participantCount,
        expectedQualifiedParticipantIndices: setup.manifestAccepted,
        signerUniverse: manifestAcceptedSet,
    });

    const encryptedShareMatrix = buildEncryptedShareMatrix(
        input.transcript,
        setup.verifiedSignatures.participantCount,
    );
    const pedersenCommitmentMap = parsePedersenCommitmentMap(
        input.transcript,
        setup.threshold,
    );

    const phase0QualSet = new Set(
        phase0Checkpoint.payload.qualifiedParticipantIndices,
    );
    const phase1Checkpoint = await resolveVerifiedPhaseCheckpoint({
        transcript: input.transcript,
        checkpointPhase: 1,
        threshold: setup.threshold,
        participantCount: setup.verifiedSignatures.participantCount,
        expectedQualifiedParticipantIndices:
            phase0Checkpoint.payload.qualifiedParticipantIndices,
        signerUniverse: phase0QualSet,
    });
    const phase1QualifiedParticipantIndices =
        phase1Checkpoint.payload.qualifiedParticipantIndices;
    assertEncryptedShareCoverage(
        encryptedShareMatrix,
        phase1QualifiedParticipantIndices,
    );
    assertPedersenCommitmentCoverage(
        pedersenCommitmentMap,
        phase1QualifiedParticipantIndices,
    );

    const activeComplaintParticipants = new Set(
        phase1QualifiedParticipantIndices,
    );
    const acceptedComplaints = await verifyComplaintOutcomes(
        input,
        setup.verifiedSignatures,
        encryptedShareMatrix,
        pedersenCommitmentMap,
        RISTRETTO_GROUP,
        activeComplaintParticipants,
    );
    const complaintBoundQualifiedParticipantIndices =
        reduceQualifiedParticipantIndices(
            phase1QualifiedParticipantIndices,
            acceptedComplaints,
        );
    const phase2Checkpoint = await resolveVerifiedPhaseCheckpoint({
        transcript: input.transcript,
        checkpointPhase: 2,
        threshold: setup.threshold,
        participantCount: setup.verifiedSignatures.participantCount,
        expectedQualifiedParticipantIndices:
            complaintBoundQualifiedParticipantIndices,
        signerUniverse: activeComplaintParticipants,
    });

    const phaseCheckpoints: FinalizedPhaseCheckpoint[] = [
        phase0Checkpoint,
        phase1Checkpoint,
        phase2Checkpoint,
    ];

    const phase2QualSet = new Set(
        phase2Checkpoint.payload.qualifiedParticipantIndices,
    );
    const phase3Checkpoint = await resolveVerifiedPhaseCheckpoint({
        transcript: input.transcript,
        checkpointPhase: 3,
        threshold: setup.threshold,
        participantCount: setup.verifiedSignatures.participantCount,
        expectedQualifiedParticipantIndices:
            phase2Checkpoint.payload.qualifiedParticipantIndices,
        signerUniverse: phase2QualSet,
    });
    phaseCheckpoints.push(phase3Checkpoint);
    const finalQualifiedParticipantIndices =
        phase3Checkpoint.payload.qualifiedParticipantIndices;

    return finalizeVerifiedTranscript(
        input,
        setup.verifiedSignatures,
        setup.manifestPublication.participantIndex,
        acceptedComplaints,
        setup.manifestAccepted,
        phaseCheckpoints,
        finalQualifiedParticipantIndices,
        RISTRETTO_GROUP,
        setup.threshold,
    );
};

/**
 * Verifies a DKG transcript, its signatures, Feldman extraction proofs,
 * the exact claimed threshold degree, accepted complaint outcomes, the DKG
 * transcript hash, and the announced joint public key.
 *
 * @param input Transcript verification input.
 * @returns Verified transcript metadata and derived ceremony material.
 */
export const verifyDKGTranscript = async (
    input: VerifyDKGTranscriptInput,
): Promise<VerifiedDKGTranscript> => {
    const auditedTranscript = await auditSignedPayloads(input.transcript);
    const manifestHash = await hashElectionManifest(input.manifest);
    validateTranscriptShape(
        {
            ...input,
            transcript: auditedTranscript.acceptedPayloads,
        },
        manifestHash,
    );
    const setup = await buildVerifiedDKGSetup(
        {
            ...input,
            transcript: auditedTranscript.acceptedPayloads,
        },
        manifestHash,
    );

    return auditedTranscript.acceptedPayloads.some(isPhaseCheckpointPayload)
        ? verifyCheckpointedDKGTranscript(
              {
                  ...input,
                  transcript: auditedTranscript.acceptedPayloads,
              },
              setup,
          )
        : verifyLegacyDKGTranscript(
              {
                  ...input,
                  transcript: auditedTranscript.acceptedPayloads,
              },
              setup,
          );
};
