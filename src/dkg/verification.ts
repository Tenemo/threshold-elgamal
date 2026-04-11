import {
    InvalidPayloadError,
    ThresholdViolationError,
    getGroup,
    majorityThreshold,
    type CryptoGroup,
} from '../core/index.js';
import type { EncodedPoint } from '../core/types.js';
import { auditSignedPayloads } from '../protocol/board-audit.js';
import {
    hashElectionManifest,
    SHIPPED_PROTOCOL_VERSION,
} from '../protocol/manifest.js';
import type { ComplaintPayload } from '../protocol/types.js';
import type { VerifiedProtocolSignatures } from '../protocol/verification.js';

import {
    isPhaseCheckpointPayload,
    type FinalizedPhaseCheckpoint,
} from './checkpoints.js';
import {
    assertSupportedCheckpointPayloads,
    resolveVerifiedPhaseCheckpoint,
} from './verification-checkpoints.js';
import {
    assertEncryptedShareCoverage,
    assertPedersenCommitmentCoverage,
    buildEncryptedShareMatrix,
    parsePedersenCommitmentMap,
    verifyComplaintOutcomes,
} from './verification-complaints.js';
import {
    deriveJointPublicKey,
    deriveQualifiedParticipantIndices,
} from './verification-derivation.js';
import {
    assertAggregateFeldmanDegree,
    parseQualifiedFeldmanCommitments,
    verifyFeldmanProofs,
    verifyKeyDerivationConfirmations,
} from './verification-feldman.js';
import {
    verifyManifestAcceptancePayloads,
    verifyManifestPublicationPayload,
    verifySignedRoster,
} from './verification-roster.js';
import {
    allParticipantIndices,
    validateTranscriptShape,
} from './verification-shared.js';
import type {
    ParsedFeldmanCommitment,
    VerifyDKGTranscriptInput,
    VerifiedDKGTranscript,
} from './verification-types.js';

export type {
    VerifyDKGTranscriptInput,
    VerifiedDKGTranscript,
} from './verification-types.js';
export {
    deriveJointPublicKey,
    deriveQualifiedParticipantIndices,
    deriveTranscriptVerificationKey,
} from './verification-derivation.js';

type VerifiedDKGSetup = {
    readonly manifestAccepted: readonly number[];
    readonly manifestPublication: Awaited<
        ReturnType<typeof verifyManifestPublicationPayload>
    >;
    readonly participantIndices: readonly number[];
    readonly threshold: number;
    readonly verifiedSignatures: VerifiedProtocolSignatures;
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

const assertQualifiedThreshold = (
    qual: readonly number[],
    threshold: number,
): void => {
    if (qual.length < threshold) {
        throw new InvalidPayloadError(
            'QUAL fell below the reconstruction threshold',
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
    qual: readonly number[],
    group: CryptoGroup,
    threshold: number,
    minimumConfirmations?: number,
): Promise<VerifiedDKGTranscript> => {
    assertQualifiedThreshold(qual, threshold);

    const feldmanCommitments = parseQualifiedFeldmanCommitments(
        input.transcript,
        qual,
        threshold,
        group,
    );
    await verifyFeldmanProofs(
        feldmanCommitments,
        SHIPPED_PROTOCOL_VERSION,
        group,
    );
    assertAggregateFeldmanDegree(feldmanCommitments);

    const normalizedFeldmanCommitments =
        normalizeFeldmanCommitments(feldmanCommitments);
    const derivedPublicKey = deriveJointPublicKey(
        normalizedFeldmanCommitments,
        group,
    );
    const qualHash = await verifyKeyDerivationConfirmations(
        input.transcript,
        qual,
        derivedPublicKey,
        group,
        minimumConfirmations,
    );

    return {
        acceptedComplaints,
        derivedPublicKey,
        feldmanCommitments: normalizedFeldmanCommitments,
        manifestAccepted,
        organizerIndex,
        participantCount: verifiedSignatures.participantCount,
        phaseCheckpoints,
        qual,
        qualHash,
        registrations: verifiedSignatures.registrations,
        rosterHash: verifiedSignatures.rosterHash,
        threshold,
    };
};

const verifyLegacyDKGTranscript = async (
    input: VerifyDKGTranscriptInput,
    setup: VerifiedDKGSetup,
    group: CryptoGroup,
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
        group,
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
        group,
        new Set(setup.participantIndices),
    );
    const qual = deriveQualifiedParticipantIndices(
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
        qual,
        group,
        setup.threshold,
    );
};

const verifyCheckpointedDKGTranscript = async (
    input: VerifyDKGTranscriptInput,
    setup: VerifiedDKGSetup,
    group: CryptoGroup,
): Promise<VerifiedDKGTranscript> => {
    assertSupportedCheckpointPayloads(input.transcript);

    const manifestAcceptedSet = new Set(setup.manifestAccepted);

    const phase0Checkpoint = await resolveVerifiedPhaseCheckpoint({
        transcript: input.transcript,
        checkpointPhase: 0,
        threshold: setup.threshold,
        participantCount: setup.verifiedSignatures.participantCount,
        signerUniverse: manifestAcceptedSet,
        qualUniverse: manifestAcceptedSet,
    });

    const encryptedShareMatrix = buildEncryptedShareMatrix(
        input.transcript,
        setup.verifiedSignatures.participantCount,
    );
    const pedersenCommitmentMap = parsePedersenCommitmentMap(
        input.transcript,
        setup.threshold,
        group,
    );

    const phase0QualSet = new Set(
        phase0Checkpoint.payload.qualParticipantIndices,
    );
    const phase1Checkpoint = await resolveVerifiedPhaseCheckpoint({
        transcript: input.transcript,
        checkpointPhase: 1,
        threshold: setup.threshold,
        participantCount: setup.verifiedSignatures.participantCount,
        signerUniverse: phase0QualSet,
        qualUniverse: phase0QualSet,
    });
    const phase1Qual = phase1Checkpoint.payload.qualParticipantIndices;
    assertEncryptedShareCoverage(encryptedShareMatrix, phase1Qual);
    assertPedersenCommitmentCoverage(pedersenCommitmentMap, phase1Qual);

    const activeComplaintParticipants = new Set(phase1Qual);
    const acceptedComplaints = await verifyComplaintOutcomes(
        input,
        setup.verifiedSignatures,
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
        threshold: setup.threshold,
        participantCount: setup.verifiedSignatures.participantCount,
        signerUniverse: activeComplaintParticipants,
        qualUniverse: new Set(complaintBoundQual),
    });

    const phaseCheckpoints: FinalizedPhaseCheckpoint[] = [
        phase0Checkpoint,
        phase1Checkpoint,
        phase2Checkpoint,
    ];

    const phase2QualSet = new Set(
        phase2Checkpoint.payload.qualParticipantIndices,
    );
    const phase3Checkpoint = await resolveVerifiedPhaseCheckpoint({
        transcript: input.transcript,
        checkpointPhase: 3,
        threshold: setup.threshold,
        participantCount: setup.verifiedSignatures.participantCount,
        signerUniverse: phase2QualSet,
        qualUniverse: phase2QualSet,
    });
    phaseCheckpoints.push(phase3Checkpoint);
    const finalQual = phase3Checkpoint.payload.qualParticipantIndices;

    return finalizeVerifiedTranscript(
        input,
        setup.verifiedSignatures,
        setup.manifestPublication.participantIndex,
        acceptedComplaints,
        setup.manifestAccepted,
        phaseCheckpoints,
        finalQual,
        group,
        setup.threshold,
        0,
    );
};

/**
 * Verifies a DKG transcript, its signatures, Feldman extraction proofs,
 * the exact claimed threshold degree, accepted complaint outcomes, `qualHash`,
 * and the announced joint public key.
 *
 * @param input Transcript verification input.
 * @returns Verified transcript metadata and derived ceremony material.
 */
export const verifyDKGTranscript = async (
    input: VerifyDKGTranscriptInput,
): Promise<VerifiedDKGTranscript> => {
    const manifestHash = await hashElectionManifest(input.manifest);
    const auditedTranscript = await auditSignedPayloads(input.transcript);
    const normalizedInput: VerifyDKGTranscriptInput = {
        ...input,
        transcript: auditedTranscript.acceptedPayloads,
    };
    const group = getGroup('ristretto255');
    validateTranscriptShape(normalizedInput, manifestHash);
    const setup = await buildVerifiedDKGSetup(normalizedInput, manifestHash);

    return normalizedInput.transcript.some(isPhaseCheckpointPayload)
        ? verifyCheckpointedDKGTranscript(normalizedInput, setup, group)
        : verifyLegacyDKGTranscript(normalizedInput, setup, group);
};
