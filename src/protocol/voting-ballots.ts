import { InvalidPayloadError } from '../core/index.js';

import {
    verifyAndAggregateBallotsByOption,
    type BallotTranscriptEntry,
    type VerifiedOptionBallotAggregation,
} from './ballots.js';
import { auditSignedPayloads } from './board-audit.js';
import type { BallotSubmissionPayload } from './types.js';
import { decodeCiphertext, decodeDisjunctiveProof } from './voting-codecs.js';
import {
    assertPhase,
    assertValidOptionIndex,
    buildVotingManifestContext,
    BALLOT_SUBMISSION_PHASE,
} from './voting-shared.js';
import type { VerifyBallotSubmissionPayloadsByOptionInput } from './voting-types.js';

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
    const ballotEntries = auditedBallots.acceptedPayloads.map((payload) => {
        if (payload.payload.sessionId !== context.sessionId) {
            throw new InvalidPayloadError(
                'Ballot submission payload session does not match the verification input',
            );
        }
        if (payload.payload.manifestHash !== context.manifestHash) {
            throw new InvalidPayloadError(
                'Ballot submission payload manifest hash does not match the verification input',
            );
        }

        return decodeBallotPayload(payload.payload, context.optionCount);
    });

    return verifyAndAggregateBallotsByOption({
        ballots: ballotEntries,
        publicKey: input.publicKey,
        validValues: context.scoreDomainValues,
        protocolVersion: context.protocolVersion,
        manifestHash: context.manifestHash,
        sessionId: context.sessionId,
        optionCount: context.optionCount,
    });
};
