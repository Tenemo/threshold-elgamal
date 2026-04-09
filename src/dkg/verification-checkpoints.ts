import { InvalidPayloadError } from '../core/index.js';
import { hashProtocolPhaseSnapshot } from '../protocol/transcript.js';
import type { SignedPayload } from '../protocol/types.js';

import {
    collectCheckpointVariants,
    isPhaseCheckpointPayload,
    requiredCheckpointPhases,
    type FinalizedPhaseCheckpoint,
} from './checkpoints.js';
import type { DKGProtocol } from './types.js';
import {
    assertIndexSubset,
    assertUniqueSortedParticipantIndices,
} from './verification-shared.js';
import type { ResolvePhaseCheckpointInput } from './verification-types.js';

export const assertSupportedCheckpointPayloads = (
    transcript: readonly SignedPayload[],
    protocol: DKGProtocol,
): void => {
    for (const signedPayload of transcript) {
        if (
            isPhaseCheckpointPayload(signedPayload) &&
            !requiredCheckpointPhases(protocol).includes(
                signedPayload.payload.checkpointPhase,
            )
        ) {
            throw new InvalidPayloadError(
                `Checkpoint phase ${signedPayload.payload.checkpointPhase} is not part of the ${protocol} phase plan`,
            );
        }
    }
};

export const resolveVerifiedPhaseCheckpoint = async (
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
