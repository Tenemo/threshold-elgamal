import {
    InvalidPayloadError,
    assertInSubgroup,
    assertMajorityThreshold,
    assertPositiveParticipantIndex,
    getGroup,
    modP,
    modPowP,
    modQ,
    type CryptoGroup,
} from '../core/index.js';
import { verifySchnorrProof, type ProofContext } from '../proofs/index.js';
import { hashElectionManifest } from '../protocol/manifest.js';
import { classifySlotConflict } from '../protocol/payloads.js';
import {
    hashProtocolPhaseSnapshot,
    hashProtocolTranscript,
} from '../protocol/transcript.js';
import type {
    ComplaintPayload,
    ComplaintResolutionPayload,
    ElectionManifest,
    EncryptedDualSharePayload,
    FeldmanCommitmentPayload,
    KeyDerivationConfirmation,
    ManifestAcceptancePayload,
    ManifestPublicationPayload,
    PedersenCommitmentPayload,
    RegistrationPayload,
    SignedPayload,
} from '../protocol/types.js';
import {
    verifySignedProtocolPayloads,
    type VerifiedProtocolSignatures,
} from '../protocol/verification.js';
import { bigintToFixedHex, fixedHexToBigint } from '../serialize/index.js';
import { resolveDealerChallengeFromPublicKey } from '../transport/complaints.js';
import { verifyPedersenShare } from '../vss/pedersen.js';
import type { PedersenShare } from '../vss/types.js';

import {
    collectCheckpointVariants,
    isPhaseCheckpointPayload,
    requiredCheckpointPhases,
    type FinalizedPhaseCheckpoint,
} from './checkpoints.js';
import { expectedDkgPhase } from './phase-plan.js';
import type { DKGProtocol } from './types.js';

const assertUniqueSlots = (transcript: readonly SignedPayload[]): void => {
    for (let leftIndex = 0; leftIndex < transcript.length; leftIndex += 1) {
        for (
            let rightIndex = leftIndex + 1;
            rightIndex < transcript.length;
            rightIndex += 1
        ) {
            const relation = classifySlotConflict(
                transcript[leftIndex],
                transcript[rightIndex],
            );
            if (relation === 'equivocation') {
                throw new InvalidPayloadError(
                    'A different payload for the same canonical slot was observed',
                );
            }
        }
    }
};

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

const parseCommitmentVector = (
    commitments: readonly string[],
    expectedLength: number,
    group: CryptoGroup,
    label: string,
): readonly bigint[] => {
    if (commitments.length !== expectedLength) {
        throw new InvalidPayloadError(
            `${label} must contain exactly ${expectedLength} commitments`,
        );
    }

    return commitments.map((commitment) => {
        const parsed = fixedHexToBigint(commitment);
        assertInSubgroup(parsed, group.p, group.q);
        return parsed;
    });
};

const buildSchnorrContext = (
    payload: FeldmanCommitmentPayload,
    coefficientIndex: number,
    group: CryptoGroup,
): ProofContext => ({
    protocolVersion: 'v1',
    suiteId: group.name,
    manifestHash: payload.manifestHash,
    sessionId: payload.sessionId,
    label: 'feldman-coefficient-proof',
    participantIndex: payload.participantIndex,
    coefficientIndex,
});

const deriveTranscriptVerificationKeyInternal = (
    commitmentSets: readonly (readonly bigint[])[],
    participantIndex: number,
    group: CryptoGroup,
): bigint => {
    assertPositiveParticipantIndex(participantIndex);
    const point = BigInt(participantIndex);

    return commitmentSets.reduce((outerAccumulator, commitments) => {
        let innerAccumulator = 1n;
        let exponent = 1n;

        for (const commitment of commitments) {
            innerAccumulator = modP(
                innerAccumulator * modPowP(commitment, exponent, group.p),
                group.p,
            );
            exponent = modQ(exponent * point, group.q);
        }

        return modP(outerAccumulator * innerAccumulator, group.p);
    }, 1n);
};

/** Share contribution accepted from one qualified dealer. */
export type AcceptedShareContribution = {
    readonly dealerIndex: number;
    readonly share: PedersenShare;
};

/** Input bundle for verifying a DKG transcript. */
export type VerifyDKGTranscriptInput = {
    readonly protocol: DKGProtocol;
    readonly transcript: readonly SignedPayload[];
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
};

/** Verified DKG transcript result with reusable derived ceremony material. */
export type VerifiedDKGTranscript = {
    readonly acceptedComplaints: readonly ComplaintPayload[];
    readonly derivedPublicKey: bigint;
    readonly feldmanCommitments: readonly {
        readonly dealerIndex: number;
        readonly commitments: readonly bigint[];
    }[];
    readonly group: CryptoGroup;
    readonly manifestAccepted: readonly number[];
    readonly phaseCheckpoints: readonly FinalizedPhaseCheckpoint[];
    readonly qual: readonly number[];
    readonly qualHash: string;
    readonly registrations: readonly SignedPayload<RegistrationPayload>[];
    readonly rosterHash: string;
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
        readonly commitments: readonly bigint[];
    }[],
    participantIndex: number,
    group: CryptoGroup,
): bigint =>
    deriveTranscriptVerificationKeyInternal(
        feldmanCommitments.map((entry) => entry.commitments),
        participantIndex,
        group,
    );

/**
 * Derives transcript verification keys for multiple participant indices.
 *
 * @param feldmanCommitments Qualified dealer commitment vectors.
 * @param participantIndices Participant indices to derive.
 * @param group Selected group.
 * @returns Indexed transcript-derived verification keys.
 */
export const deriveTranscriptVerificationKeys = (
    feldmanCommitments: readonly {
        readonly dealerIndex: number;
        readonly commitments: readonly bigint[];
    }[],
    participantIndices: readonly number[],
    group: CryptoGroup,
): readonly { readonly index: number; readonly value: bigint }[] =>
    participantIndices.map((index) => ({
        index,
        value: deriveTranscriptVerificationKey(
            feldmanCommitments,
            index,
            group,
        ),
    }));

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
        readonly commitments: readonly bigint[];
    }[],
    group: CryptoGroup,
): bigint =>
    feldmanCommitments.reduce(
        (product, entry) => modP(product * entry.commitments[0], group.p),
        1n,
    );

/**
 * Derives one participant's final share by summing accepted share
 * contributions from qualified dealers.
 *
 * @param contributions Local accepted share contributions.
 * @param qual Qualified dealer indices.
 * @param participantIndex Recipient participant index.
 * @param q Prime-order subgroup order.
 * @returns Final indexed share for the participant.
 */
export const deriveFinalShare = (
    contributions: readonly AcceptedShareContribution[],
    qual: readonly number[],
    participantIndex: number,
    q: bigint,
): { readonly index: number; readonly value: bigint } => {
    assertPositiveParticipantIndex(participantIndex);
    const qualSet = new Set(qual);
    const relevant = contributions.filter(
        (contribution) =>
            qualSet.has(contribution.dealerIndex) &&
            contribution.share.index === participantIndex,
    );

    if (relevant.length !== qual.length) {
        throw new InvalidPayloadError(
            `Final share derivation requires one accepted contribution from every qualified dealer for participant ${participantIndex}`,
        );
    }

    return {
        index: participantIndex,
        value: modQ(
            relevant.reduce(
                (sum, contribution) => sum + contribution.share.secretValue,
                0n,
            ),
            q,
        ),
    };
};

/**
 * Derives the qualified participant set from accepted complaint outcomes.
 *
 * @param participantCount Total participant count.
 * @param acceptedComplaints Complaint set resolved in the dealer-fault branch.
 * @returns Qualified participant indices.
 */
export const deriveQualifiedParticipantIndices = (
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

const complaintResolutionKey = (
    complainantIndex: number,
    dealerIndex: number,
    envelopeId: string,
): string => `${complainantIndex}:${dealerIndex}:${envelopeId}`;

const encryptedShareSlotKey = (
    dealerIndex: number,
    recipientIndex: number,
): string => `${dealerIndex}:${recipientIndex}`;

type EncryptedShareMatrix = {
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
    readonly commitments: readonly bigint[];
    readonly payload: FeldmanCommitmentPayload;
};

const validateParticipantIndex = (
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

const assertUniqueSortedParticipantIndices = (
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
        const expected = expectedDkgPhase(
            input.protocol,
            signedPayload.payload.messageType,
            isPhaseCheckpointPayload(signedPayload)
                ? signedPayload.payload
                : undefined,
        );
        if (expected === null || signedPayload.payload.phase !== expected) {
            throw new InvalidPayloadError(
                `Payload phase does not match the ${input.protocol} phase plan`,
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

const verifySignedRoster = async (
    transcript: readonly SignedPayload[],
    participantCount: number,
    expectedRosterHash: string,
): Promise<VerifiedProtocolSignatures> => {
    assertUniqueSlots(transcript);

    const verifiedSignatures = await verifySignedProtocolPayloads(
        transcript,
        participantCount,
    );
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
): Promise<void> => {
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
};

const verifyManifestAcceptancePayloads = (
    transcript: readonly SignedPayload[],
    participantCount: number,
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

    return acceptances
        .map((acceptance) => acceptance.participantIndex)
        .sort((left, right) => left - right);
};

const assertIndexSubset = (
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

type ResolvePhaseCheckpointInput = {
    readonly transcript: readonly SignedPayload[];
    readonly checkpointPhase: number;
    readonly threshold: number;
    readonly participantCount: number;
    readonly signerUniverse: ReadonlySet<number>;
    readonly qualUniverse: ReadonlySet<number>;
};

const resolveVerifiedPhaseCheckpoint = async (
    input: ResolvePhaseCheckpointInput,
): Promise<FinalizedPhaseCheckpoint> => {
    const supported = collectCheckpointVariants(
        input.transcript,
        input.checkpointPhase,
    ).filter((entry) => entry.signatures.length >= input.threshold);

    if (supported.length === 0) {
        throw new InvalidPayloadError(
            `Missing threshold-supported phase checkpoint for phase ${input.checkpointPhase}`,
        );
    }
    if (supported.length > 1) {
        throw new InvalidPayloadError(
            `Observed multiple threshold-supported phase checkpoints for phase ${input.checkpointPhase}`,
        );
    }

    const checkpoint = supported[0];
    const qual = checkpoint.payload.qualParticipantIndices;

    assertUniqueSortedParticipantIndices(
        qual,
        input.participantCount,
        `Phase ${input.checkpointPhase} checkpoint QUAL participant`,
    );
    if (qual.length < input.threshold) {
        throw new InvalidPayloadError(
            `Checkpoint QUAL for phase ${input.checkpointPhase} must contain at least ${input.threshold} participants`,
        );
    }

    const expectedSnapshotHash = await hashProtocolPhaseSnapshot(
        input.transcript.map((entry) => entry.payload),
        input.checkpointPhase,
    );
    if (checkpoint.payload.checkpointTranscriptHash !== expectedSnapshotHash) {
        throw new InvalidPayloadError(
            `Phase ${input.checkpointPhase} checkpoint transcript hash does not match the signed transcript snapshot`,
        );
    }

    assertIndexSubset(
        qual,
        input.qualUniverse,
        `Phase ${input.checkpointPhase} checkpoint QUAL participant`,
    );
    assertIndexSubset(
        checkpoint.signers,
        input.signerUniverse,
        `Phase ${input.checkpointPhase} checkpoint signer`,
    );

    const qualSet = new Set(qual);
    for (const signer of checkpoint.signers) {
        if (!qualSet.has(signer)) {
            throw new InvalidPayloadError(
                `Phase ${input.checkpointPhase} checkpoint signer ${signer} is not part of the checkpoint QUAL set`,
            );
        }
    }

    return checkpoint;
};

const buildEncryptedShareMatrix = (
    transcript: readonly SignedPayload[],
    participantCount: number,
): EncryptedShareMatrix => {
    const encryptedShares = transcript.filter(
        (payload): payload is SignedPayload<EncryptedDualSharePayload> =>
            payload.payload.messageType === 'encrypted-dual-share',
    );

    const bySlot = new Map<string, SignedPayload<EncryptedDualSharePayload>>();
    const byComplaintKey = new Map<
        string,
        SignedPayload<EncryptedDualSharePayload>
    >();

    for (const payload of encryptedShares) {
        const dealerIndex = payload.payload.participantIndex;
        const recipientIndex = payload.payload.recipientIndex;

        validateParticipantIndex(
            dealerIndex,
            participantCount,
            'Encrypted share dealer index',
        );
        validateParticipantIndex(
            recipientIndex,
            participantCount,
            'Encrypted share recipient index',
        );

        if (dealerIndex === recipientIndex) {
            throw new InvalidPayloadError(
                `Encrypted share payload for dealer ${dealerIndex} must target a different recipient`,
            );
        }

        const slotKey = encryptedShareSlotKey(dealerIndex, recipientIndex);
        if (bySlot.has(slotKey)) {
            throw new InvalidPayloadError(
                `Duplicate encrypted share payload for dealer ${dealerIndex} and recipient ${recipientIndex}`,
            );
        }
        bySlot.set(slotKey, payload);

        const complaintKey = complaintResolutionKey(
            recipientIndex,
            dealerIndex,
            payload.payload.envelopeId,
        );
        if (byComplaintKey.has(complaintKey)) {
            throw new InvalidPayloadError(
                `Duplicate encrypted share envelope ${payload.payload.envelopeId} for dealer ${dealerIndex} and recipient ${recipientIndex}`,
            );
        }
        byComplaintKey.set(complaintKey, payload);
    }

    return {
        encryptedShares,
        bySlot,
        byComplaintKey,
    };
};

const assertEncryptedShareCoverage = (
    encryptedShareMatrix: EncryptedShareMatrix,
    participantIndices: readonly number[],
): void => {
    for (const dealerIndex of participantIndices) {
        for (const recipientIndex of participantIndices) {
            if (dealerIndex === recipientIndex) {
                continue;
            }

            if (
                !encryptedShareMatrix.bySlot.has(
                    encryptedShareSlotKey(dealerIndex, recipientIndex),
                )
            ) {
                throw new InvalidPayloadError(
                    `Missing encrypted share payload for dealer ${dealerIndex} and recipient ${recipientIndex}`,
                );
            }
        }
    }
};

const parsePedersenCommitmentMap = (
    transcript: readonly SignedPayload[],
    protocol: DKGProtocol,
    threshold: number,
    group: CryptoGroup,
): ReadonlyMap<number, readonly bigint[]> => {
    const pedersenCommitments = transcript.filter(
        (payload): payload is SignedPayload<PedersenCommitmentPayload> =>
            payload.payload.messageType === 'pedersen-commitment',
    );
    if (protocol !== 'gjkr' && pedersenCommitments.length > 0) {
        throw new InvalidPayloadError(
            'Joint-Feldman transcripts must not include Pedersen commitments',
        );
    }

    const pedersenCommitmentMap = new Map<number, readonly bigint[]>();
    for (const payload of pedersenCommitments) {
        if (pedersenCommitmentMap.has(payload.payload.participantIndex)) {
            throw new InvalidPayloadError(
                `Pedersen commitment requires exactly one payload for participant ${payload.payload.participantIndex}`,
            );
        }
        pedersenCommitmentMap.set(
            payload.payload.participantIndex,
            parseCommitmentVector(
                payload.payload.commitments,
                threshold,
                group,
                'Pedersen commitment payload',
            ),
        );
    }

    return pedersenCommitmentMap;
};

const assertPedersenCommitmentCoverage = (
    pedersenCommitmentMap: ReadonlyMap<number, readonly bigint[]>,
    dealerIndices: readonly number[],
): void => {
    for (const dealerIndex of dealerIndices) {
        if (!pedersenCommitmentMap.has(dealerIndex)) {
            throw new InvalidPayloadError(
                `Missing Pedersen commitment payload for dealer ${dealerIndex}`,
            );
        }
    }
};

const buildComplaintResolutionPayloadMap = (
    transcript: readonly SignedPayload[],
): {
    readonly complaintResolutionPayloads: readonly ComplaintResolutionPayload[];
    readonly resolutionPayloadMap: ReadonlyMap<
        string,
        ComplaintResolutionPayload
    >;
} => {
    const complaintResolutionPayloads = transcript
        .filter(
            (payload): payload is SignedPayload<ComplaintResolutionPayload> =>
                payload.payload.messageType === 'complaint-resolution',
        )
        .map((payload) => payload.payload);
    const resolutionPayloadMap = new Map<string, ComplaintResolutionPayload>();

    for (const resolutionPayload of complaintResolutionPayloads) {
        if (
            resolutionPayload.participantIndex !== resolutionPayload.dealerIndex
        ) {
            throw new InvalidPayloadError(
                `Complaint resolution for envelope ${resolutionPayload.envelopeId} must be authored by dealer ${resolutionPayload.dealerIndex}`,
            );
        }

        const key = complaintResolutionKey(
            resolutionPayload.complainantIndex,
            resolutionPayload.dealerIndex,
            resolutionPayload.envelopeId,
        );
        if (resolutionPayloadMap.has(key)) {
            throw new InvalidPayloadError(
                `Duplicate complaint resolution for envelope ${resolutionPayload.envelopeId}`,
            );
        }
        resolutionPayloadMap.set(key, resolutionPayload);
    }

    return {
        complaintResolutionPayloads,
        resolutionPayloadMap,
    };
};

function parsePedersenSharePlaintext(
    plaintext: Uint8Array,
    expectedParticipantIndex: number,
): PedersenShare {
    let parsed: {
        readonly blindingValue: string;
        readonly index: number;
        readonly secretValue: string;
    };

    try {
        parsed = JSON.parse(new TextDecoder().decode(plaintext)) as {
            readonly blindingValue: string;
            readonly index: number;
            readonly secretValue: string;
        };
    } catch {
        throw new InvalidPayloadError(
            'Complaint resolution plaintext is not valid canonical JSON',
        );
    }

    if (parsed.index !== expectedParticipantIndex) {
        throw new InvalidPayloadError(
            `Complaint resolution share index mismatch: expected ${expectedParticipantIndex}, received ${parsed.index}`,
        );
    }

    return {
        index: parsed.index,
        secretValue: fixedHexToBigint(parsed.secretValue),
        blindingValue: fixedHexToBigint(parsed.blindingValue),
    };
}

const verifyComplaintOutcomes = async (
    input: VerifyDKGTranscriptInput,
    verifiedSignatures: VerifiedProtocolSignatures,
    encryptedShareMatrix: EncryptedShareMatrix,
    pedersenCommitmentMap: ReadonlyMap<number, readonly bigint[]>,
    group: CryptoGroup,
    allowedParticipants: ReadonlySet<number>,
): Promise<readonly ComplaintPayload[]> => {
    const complaints = input.transcript
        .filter(
            (payload): payload is SignedPayload<ComplaintPayload> =>
                payload.payload.messageType === 'complaint',
        )
        .map((payload) => payload.payload);
    const { complaintResolutionPayloads, resolutionPayloadMap } =
        buildComplaintResolutionPayloadMap(input.transcript);
    const rosterEntryMap = new Map(
        verifiedSignatures.rosterEntries.map((entry) => [
            entry.participantIndex,
            entry,
        ]),
    );
    const acceptedComplaints: ComplaintPayload[] = [];
    const usedResolutionKeys = new Set<string>();

    for (const complaint of complaints) {
        if (
            !allowedParticipants.has(complaint.participantIndex) ||
            !allowedParticipants.has(complaint.dealerIndex)
        ) {
            throw new InvalidPayloadError(
                `Complaint participants must belong to the active DKG set for phase ${complaint.phase}`,
            );
        }

        const resolutionKey = complaintResolutionKey(
            complaint.participantIndex,
            complaint.dealerIndex,
            complaint.envelopeId,
        );
        const matchingEnvelope =
            encryptedShareMatrix.byComplaintKey.get(resolutionKey);
        if (matchingEnvelope === undefined) {
            throw new InvalidPayloadError(
                `Complaint references an unknown envelope ${complaint.envelopeId} for dealer ${complaint.dealerIndex} and complainant ${complaint.participantIndex}`,
            );
        }

        const resolutionPayload = resolutionPayloadMap.get(resolutionKey);
        if (resolutionPayload === undefined) {
            acceptedComplaints.push(complaint);
            continue;
        }

        usedResolutionKeys.add(resolutionKey);

        if (resolutionPayload.suite !== matchingEnvelope.payload.suite) {
            throw new InvalidPayloadError(
                `Complaint resolution suite mismatch for envelope ${complaint.envelopeId}`,
            );
        }

        const complainantRosterEntry = rosterEntryMap.get(
            complaint.participantIndex,
        );
        if (complainantRosterEntry === undefined) {
            throw new InvalidPayloadError(
                `Missing roster entry for complainant ${complaint.participantIndex}`,
            );
        }

        const resolution = await resolveDealerChallengeFromPublicKey(
            {
                ...matchingEnvelope.payload,
                dealerIndex: matchingEnvelope.payload.participantIndex,
                rosterHash: input.manifest.rosterHash,
                payloadType: 'encrypted-dual-share',
                protocolVersion: input.manifest.protocolVersion,
            },
            complainantRosterEntry.transportPublicKey,
            resolutionPayload.revealedEphemeralPrivateKey,
        );
        if (resolution.valid !== true || resolution.plaintext === undefined) {
            throw new InvalidPayloadError(
                `Complaint resolution failed verification for complainant ${complaint.participantIndex} against dealer ${complaint.dealerIndex}`,
            );
        }

        const decryptedShare = parsePedersenSharePlaintext(
            resolution.plaintext,
            complaint.participantIndex,
        );
        const dealerCommitments = pedersenCommitmentMap.get(
            complaint.dealerIndex,
        );
        if (input.protocol === 'gjkr') {
            if (dealerCommitments === undefined) {
                throw new InvalidPayloadError(
                    `Missing Pedersen commitments for dealer ${complaint.dealerIndex}`,
                );
            }
            if (
                !verifyPedersenShare(
                    decryptedShare,
                    {
                        commitments: dealerCommitments,
                    },
                    group,
                )
            ) {
                throw new InvalidPayloadError(
                    `Complaint resolution share failed Pedersen verification for dealer ${complaint.dealerIndex} and complainant ${complaint.participantIndex}`,
                );
            }
        } else if (complaint.reason === 'pedersen-failure') {
            throw new InvalidPayloadError(
                'Joint-Feldman transcripts cannot resolve Pedersen-failure complaints',
            );
        }
    }

    for (const resolutionPayload of complaintResolutionPayloads) {
        if (
            !allowedParticipants.has(resolutionPayload.participantIndex) ||
            !allowedParticipants.has(resolutionPayload.dealerIndex) ||
            !allowedParticipants.has(resolutionPayload.complainantIndex)
        ) {
            throw new InvalidPayloadError(
                `Complaint resolution participants must belong to the active DKG set for phase ${resolutionPayload.phase}`,
            );
        }

        const key = complaintResolutionKey(
            resolutionPayload.complainantIndex,
            resolutionPayload.dealerIndex,
            resolutionPayload.envelopeId,
        );
        if (!usedResolutionKeys.has(key)) {
            throw new InvalidPayloadError(
                `Complaint resolution for envelope ${resolutionPayload.envelopeId} does not match any complaint`,
            );
        }
    }

    return acceptedComplaints;
};

const parseQualifiedFeldmanCommitments = (
    transcript: readonly SignedPayload[],
    qual: readonly number[],
    threshold: number,
    group: CryptoGroup,
): readonly ParsedFeldmanCommitment[] => {
    const feldmanPayloads = transcript.filter(
        (payload): payload is SignedPayload<FeldmanCommitmentPayload> =>
            payload.payload.messageType === 'feldman-commitment',
    );

    return qual.map((participantIndex) => {
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
            group,
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
    group: CryptoGroup,
): Promise<void> => {
    for (const entry of feldmanCommitments) {
        for (const [offset, commitment] of entry.commitments.entries()) {
            const proof = entry.payload.proofs[offset];
            const valid = await verifySchnorrProof(
                {
                    challenge: fixedHexToBigint(proof.challenge),
                    response: fixedHexToBigint(proof.response),
                },
                commitment,
                group,
                buildSchnorrContext(entry.payload, offset + 1, group),
            );
            if (!valid) {
                throw new InvalidPayloadError(
                    `Feldman Schnorr proof failed verification for participant ${entry.dealerIndex} coefficient ${offset + 1}`,
                );
            }
        }
    }
};

const verifyKeyDerivationConfirmations = async (
    transcript: readonly SignedPayload[],
    qual: readonly number[],
    derivedPublicKey: bigint,
    group: CryptoGroup,
    minimumConfirmations = qual.length,
): Promise<string> => {
    const qualSet = new Set(qual);
    const preConfirmationTranscript = transcript.filter(
        (payload) =>
            payload.payload.messageType !== 'key-derivation-confirmation',
    );
    const qualHash = await hashProtocolTranscript(
        preConfirmationTranscript.map((payload) => payload.payload),
        group.byteLength,
    );
    const expectedPublicKeyHex = bigintToFixedHex(
        derivedPublicKey,
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
        if (!qualSet.has(confirmation.payload.participantIndex)) {
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

        if (confirmation.payload.qualHash !== qualHash) {
            throw new InvalidPayloadError(
                `qualHash mismatch in confirmation from participant ${confirmation.payload.participantIndex}`,
            );
        }
        if (confirmation.payload.publicKey !== expectedPublicKeyHex) {
            throw new InvalidPayloadError(
                `Joint public key mismatch in confirmation from participant ${confirmation.payload.participantIndex}`,
            );
        }
    }

    return qualHash;
};

const reduceQualifiedParticipantIndices = (
    qual: readonly number[],
    acceptedComplaints: readonly ComplaintPayload[],
): readonly number[] => {
    const disqualifiedDealers = new Set(
        acceptedComplaints.map((complaint) => complaint.dealerIndex),
    );

    return qual.filter(
        (participantIndex) => !disqualifiedDealers.has(participantIndex),
    );
};

const verifyLegacyDKGTranscript = async (
    input: VerifyDKGTranscriptInput,
    manifestHash: string,
    group: CryptoGroup,
    threshold: number,
): Promise<VerifiedDKGTranscript> => {
    const verifiedSignatures = await verifySignedRoster(
        input.transcript,
        input.manifest.participantCount,
        input.manifest.rosterHash,
    );
    await verifyManifestPublicationPayload(input.transcript, manifestHash);
    const manifestAccepted = verifyManifestAcceptancePayloads(
        input.transcript,
        input.manifest.participantCount,
        input.manifest.rosterHash,
        true,
    );

    const encryptedShareMatrix = buildEncryptedShareMatrix(
        input.transcript,
        input.manifest.participantCount,
    );
    assertEncryptedShareCoverage(
        encryptedShareMatrix,
        Array.from(
            { length: input.manifest.participantCount },
            (_value, index) => index + 1,
        ),
    );

    const pedersenCommitmentMap = parsePedersenCommitmentMap(
        input.transcript,
        input.protocol,
        threshold,
        group,
    );
    if (input.protocol === 'gjkr') {
        assertPedersenCommitmentCoverage(
            pedersenCommitmentMap,
            Array.from(
                { length: input.manifest.participantCount },
                (_value, index) => index + 1,
            ),
        );
    }

    const acceptedComplaints = await verifyComplaintOutcomes(
        input,
        verifiedSignatures,
        encryptedShareMatrix,
        pedersenCommitmentMap,
        group,
        new Set(
            Array.from(
                { length: input.manifest.participantCount },
                (_value, index) => index + 1,
            ),
        ),
    );
    const qual = deriveQualifiedParticipantIndices(
        input.manifest.participantCount,
        acceptedComplaints,
    );
    if (qual.length < threshold) {
        throw new InvalidPayloadError(
            'QUAL fell below the reconstruction threshold',
        );
    }

    const feldmanCommitments = parseQualifiedFeldmanCommitments(
        input.transcript,
        qual,
        threshold,
        group,
    );
    await verifyFeldmanProofs(feldmanCommitments, group);

    const derivedPublicKey = deriveJointPublicKey(feldmanCommitments, group);
    const qualHash = await verifyKeyDerivationConfirmations(
        input.transcript,
        qual,
        derivedPublicKey,
        group,
    );

    return {
        acceptedComplaints,
        derivedPublicKey,
        feldmanCommitments: feldmanCommitments.map((entry) => ({
            dealerIndex: entry.dealerIndex,
            commitments: entry.commitments,
        })),
        group,
        manifestAccepted,
        phaseCheckpoints: [],
        qual,
        qualHash,
        registrations: verifiedSignatures.registrations,
        rosterHash: verifiedSignatures.rosterHash,
    };
};

const verifyCheckpointedDKGTranscript = async (
    input: VerifyDKGTranscriptInput,
    manifestHash: string,
    group: CryptoGroup,
    threshold: number,
): Promise<VerifiedDKGTranscript> => {
    for (const signedPayload of input.transcript) {
        if (
            isPhaseCheckpointPayload(signedPayload) &&
            !requiredCheckpointPhases(input.protocol).includes(
                signedPayload.payload.checkpointPhase,
            )
        ) {
            throw new InvalidPayloadError(
                `Checkpoint phase ${signedPayload.payload.checkpointPhase} is not part of the ${input.protocol} phase plan`,
            );
        }
    }

    const verifiedSignatures = await verifySignedRoster(
        input.transcript,
        input.manifest.participantCount,
        input.manifest.rosterHash,
    );
    await verifyManifestPublicationPayload(input.transcript, manifestHash);
    const manifestAccepted = verifyManifestAcceptancePayloads(
        input.transcript,
        input.manifest.participantCount,
        input.manifest.rosterHash,
        false,
    );
    const manifestAcceptedSet = new Set(manifestAccepted);

    const phase0Checkpoint = await resolveVerifiedPhaseCheckpoint({
        transcript: input.transcript,
        checkpointPhase: 0,
        threshold,
        participantCount: input.manifest.participantCount,
        signerUniverse: manifestAcceptedSet,
        qualUniverse: manifestAcceptedSet,
    });

    const encryptedShareMatrix = buildEncryptedShareMatrix(
        input.transcript,
        input.manifest.participantCount,
    );
    const pedersenCommitmentMap = parsePedersenCommitmentMap(
        input.transcript,
        input.protocol,
        threshold,
        group,
    );

    const phase0QualSet = new Set(
        phase0Checkpoint.payload.qualParticipantIndices,
    );
    const phase1Checkpoint = await resolveVerifiedPhaseCheckpoint({
        transcript: input.transcript,
        checkpointPhase: 1,
        threshold,
        participantCount: input.manifest.participantCount,
        signerUniverse: phase0QualSet,
        qualUniverse: phase0QualSet,
    });
    const phase1Qual = phase1Checkpoint.payload.qualParticipantIndices;
    assertEncryptedShareCoverage(encryptedShareMatrix, phase1Qual);
    if (input.protocol === 'gjkr') {
        assertPedersenCommitmentCoverage(pedersenCommitmentMap, phase1Qual);
    }

    const activeComplaintParticipants = new Set(phase1Qual);
    const acceptedComplaints = await verifyComplaintOutcomes(
        input,
        verifiedSignatures,
        encryptedShareMatrix,
        pedersenCommitmentMap,
        group,
        activeComplaintParticipants,
    );
    const complaintBoundQual = reduceQualifiedParticipantIndices(
        phase1Qual,
        acceptedComplaints,
    );
    const phase2Checkpoint = await resolveVerifiedPhaseCheckpoint({
        transcript: input.transcript,
        checkpointPhase: 2,
        threshold,
        participantCount: input.manifest.participantCount,
        signerUniverse: activeComplaintParticipants,
        qualUniverse: new Set(complaintBoundQual),
    });

    const phaseCheckpoints: FinalizedPhaseCheckpoint[] = [
        phase0Checkpoint,
        phase1Checkpoint,
        phase2Checkpoint,
    ];

    let finalQual = phase2Checkpoint.payload.qualParticipantIndices;
    if (input.protocol === 'gjkr') {
        const phase2QualSet = new Set(finalQual);
        const phase3Checkpoint = await resolveVerifiedPhaseCheckpoint({
            transcript: input.transcript,
            checkpointPhase: 3,
            threshold,
            participantCount: input.manifest.participantCount,
            signerUniverse: phase2QualSet,
            qualUniverse: phase2QualSet,
        });
        phaseCheckpoints.push(phase3Checkpoint);
        finalQual = phase3Checkpoint.payload.qualParticipantIndices;
    }

    if (finalQual.length < threshold) {
        throw new InvalidPayloadError(
            'QUAL fell below the reconstruction threshold',
        );
    }

    const feldmanCommitments = parseQualifiedFeldmanCommitments(
        input.transcript,
        finalQual,
        threshold,
        group,
    );
    await verifyFeldmanProofs(feldmanCommitments, group);

    const derivedPublicKey = deriveJointPublicKey(feldmanCommitments, group);
    const qualHash = await verifyKeyDerivationConfirmations(
        input.transcript,
        finalQual,
        derivedPublicKey,
        group,
        0,
    );

    return {
        acceptedComplaints,
        derivedPublicKey,
        feldmanCommitments: feldmanCommitments.map((entry) => ({
            dealerIndex: entry.dealerIndex,
            commitments: entry.commitments,
        })),
        group,
        manifestAccepted,
        phaseCheckpoints,
        qual: finalQual,
        qualHash,
        registrations: verifiedSignatures.registrations,
        rosterHash: verifiedSignatures.rosterHash,
    };
};

/**
 * Verifies a DKG transcript, its signatures, Feldman extraction proofs,
 * accepted complaint outcomes, `qualHash`, and the announced joint public key.
 *
 * @param input Transcript verification input.
 * @returns Verified transcript metadata and derived ceremony material.
 */
export const verifyDKGTranscript = async (
    input: VerifyDKGTranscriptInput,
): Promise<VerifiedDKGTranscript> => {
    const manifestHash = await hashElectionManifest(input.manifest);
    const group = getGroup(input.manifest.suiteId);
    const threshold = assertMajorityThreshold(
        input.manifest.threshold,
        input.manifest.participantCount,
    );
    validateTranscriptShape(input, manifestHash);

    return input.transcript.some(isPhaseCheckpointPayload)
        ? verifyCheckpointedDKGTranscript(input, manifestHash, group, threshold)
        : verifyLegacyDKGTranscript(input, manifestHash, group, threshold);
};
