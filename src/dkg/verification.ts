import {
    InvalidPayloadError,
    assertMajorityThreshold,
    getGroup,
    type CryptoGroup,
} from '../core/index.js';
import { hashElectionManifest } from '../protocol/manifest.js';
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
    AcceptedShareContribution,
    VerifyDKGTranscriptInput,
    VerifiedDKGTranscript,
} from './verification-types.js';
export {
    deriveFinalShare,
    deriveJointPublicKey,
    deriveQualifiedParticipantIndices,
    deriveTranscriptVerificationKey,
    deriveTranscriptVerificationKeys,
} from './verification-derivation.js';

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
    readonly commitments: readonly bigint[];
}[] =>
    feldmanCommitments.map((entry) => ({
        dealerIndex: entry.dealerIndex,
        commitments: entry.commitments,
    }));

const finalizeVerifiedTranscript = async (
    input: VerifyDKGTranscriptInput,
    verifiedSignatures: VerifiedProtocolSignatures,
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
    await verifyFeldmanProofs(feldmanCommitments, group);

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
        group,
        manifestAccepted,
        phaseCheckpoints,
        qual,
        qualHash,
        registrations: verifiedSignatures.registrations,
        rosterHash: verifiedSignatures.rosterHash,
    };
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

    const participantIndices = allParticipantIndices(
        input.manifest.participantCount,
    );
    const encryptedShareMatrix = buildEncryptedShareMatrix(
        input.transcript,
        input.manifest.participantCount,
    );
    assertEncryptedShareCoverage(encryptedShareMatrix, participantIndices);

    const pedersenCommitmentMap = parsePedersenCommitmentMap(
        input.transcript,
        input.protocol,
        threshold,
        group,
    );
    if (input.protocol === 'gjkr') {
        assertPedersenCommitmentCoverage(
            pedersenCommitmentMap,
            participantIndices,
        );
    }

    const acceptedComplaints = await verifyComplaintOutcomes(
        input,
        verifiedSignatures,
        encryptedShareMatrix,
        pedersenCommitmentMap,
        group,
        new Set(participantIndices),
    );
    const qual = deriveQualifiedParticipantIndices(
        input.manifest.participantCount,
        acceptedComplaints,
    );

    return finalizeVerifiedTranscript(
        input,
        verifiedSignatures,
        acceptedComplaints,
        manifestAccepted,
        [],
        qual,
        group,
        threshold,
    );
};

const verifyCheckpointedDKGTranscript = async (
    input: VerifyDKGTranscriptInput,
    manifestHash: string,
    group: CryptoGroup,
    threshold: number,
): Promise<VerifiedDKGTranscript> => {
    assertSupportedCheckpointPayloads(input.transcript, input.protocol);

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

    return finalizeVerifiedTranscript(
        input,
        verifiedSignatures,
        acceptedComplaints,
        manifestAccepted,
        phaseCheckpoints,
        finalQual,
        group,
        threshold,
        0,
    );
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
