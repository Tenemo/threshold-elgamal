import { InvalidPayloadError } from '../core/index.js';

import {
    verifyAndAggregateBallotsByOption,
    type BallotTranscriptEntry,
    type VerifiedOptionBallotAggregation,
} from './ballots.js';
import { auditSignedPayloads } from './board-audit.js';
import type {
    BallotSubmissionPayload,
    SignedPayload,
    VerifyBallotSubmissionPayloadsByOptionInput,
} from './types.js';
import { decodeCiphertext, decodeDisjunctiveProof } from './voting-codecs.js';
import {
    assertPhase,
    assertValidOptionIndex,
    buildVotingManifestContext,
    BALLOT_SUBMISSION_PHASE,
} from './voting-shared.js';

const decodeBallotPayload = (
    payload: BallotSubmissionPayload,
    optionCount: number,
): BallotTranscriptEntry => {
    assertPhase(payload, BALLOT_SUBMISSION_PHASE, 'Ballot submission');
    assertValidOptionIndex(
        payload.optionIndex,
        optionCount,
        'Ballot submission',
    );

    return {
        voterIndex: payload.participantIndex,
        optionIndex: payload.optionIndex,
        ciphertext: decodeCiphertext(payload.ciphertext),
        proof: decodeDisjunctiveProof(payload.proof),
    };
};

const verifyAuditedBallotSubmissionPayloadsByOption = async (input: {
    readonly ballotPayloads: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly context: Awaited<ReturnType<typeof buildVotingManifestContext>>;
    readonly publicKey: VerifyBallotSubmissionPayloadsByOptionInput['publicKey'];
}): Promise<readonly VerifiedOptionBallotAggregation[]> => {
    const ballotEntries = input.ballotPayloads.map((payload) => {
        if (payload.payload.sessionId !== input.context.sessionId) {
            throw new InvalidPayloadError(
                'Ballot submission payload session does not match the verification input',
            );
        }
        if (payload.payload.manifestHash !== input.context.manifestHash) {
            throw new InvalidPayloadError(
                'Ballot submission payload manifest hash does not match the verification input',
            );
        }

        return decodeBallotPayload(payload.payload, input.context.optionCount);
    });

    return verifyAndAggregateBallotsByOption({
        ballots: ballotEntries,
        publicKey: input.publicKey,
        validValues: input.context.scoreDomainValues,
        protocolVersion: input.context.protocolVersion,
        manifestHash: input.context.manifestHash,
        sessionId: input.context.sessionId,
        optionCount: input.context.optionCount,
    });
};

/**
 * Verifies typed ballot-submission payloads and recomputes one aggregate tally
 * ciphertext per manifest option.
 *
 * Signatures are expected to have been checked already against the frozen
 * registration roster.
 *
 * @param input Typed ballot verification input.
 * @returns Ordered per-option additive ballot aggregations.
 */
export const verifyBallotSubmissionPayloadsByOption = async (
    input: VerifyBallotSubmissionPayloadsByOptionInput,
): Promise<readonly VerifiedOptionBallotAggregation[]> => {
    const context = await buildVotingManifestContext(
        input.manifest,
        input.sessionId,
    );
    const auditedBallots = await auditSignedPayloads(input.ballotPayloads);

    return verifyAuditedBallotSubmissionPayloadsByOption({
        ballotPayloads: auditedBallots.acceptedPayloads,
        context,
        publicKey: input.publicKey,
    });
};
