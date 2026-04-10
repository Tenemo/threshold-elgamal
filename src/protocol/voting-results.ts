import { InvalidPayloadError } from '../core/index.js';
import { decodeScalar } from '../core/ristretto.js';
import { verifyDKGTranscript } from '../dkg/verification.js';
import { combineDecryptionShares } from '../threshold/index.js';

import type { VerifiedOptionBallotAggregation } from './ballots.js';
import { auditSignedPayloads } from './board-audit.js';
import type { SignedPayload, TallyPublicationPayload } from './types.js';
import { verifyBallotSubmissionPayloadsByOption } from './voting-ballots.js';
import { verifyDecryptionSharePayloadsByOption } from './voting-decryption.js';
import {
    assertPhase,
    assertSingleOptionManifest,
    assertUniqueSortedIndices,
    assertValidOptionIndex,
    buildVotingManifestContext,
    sameNumberSet,
    TALLY_PUBLICATION_PHASE,
    verifyPayloadsAgainstRegistrations,
} from './voting-shared.js';
import type {
    VerifyPublishedVotingResultInput,
    VerifyPublishedVotingResultsInput,
    VerifiedDecryptionSharePayload,
    VerifiedPublishedOptionVotingResult,
    VerifiedPublishedVotingResult,
    VerifiedPublishedVotingResults,
} from './voting-types.js';

function recomputePublishedTally(
    ballots: VerifiedOptionBallotAggregation,
    decryptionShares: readonly VerifiedDecryptionSharePayload[],
): bigint {
    const bound = BigInt(ballots.aggregate.ballotCount) * 10n;

    return combineDecryptionShares(
        ballots.aggregate.ciphertext,
        decryptionShares.map((entry) => entry.share),
        bound,
    );
}

function verifyPublishedTallyPayload(
    payload: TallyPublicationPayload,
    optionIndex: number,
    ballots: VerifiedOptionBallotAggregation,
    decryptionShares: readonly VerifiedDecryptionSharePayload[],
    tally: bigint,
): void {
    if (payload.transcriptHash !== ballots.aggregate.transcriptHash) {
        throw new InvalidPayloadError(
            `Tally publication transcript hash does not match the accepted ballot transcript for option ${optionIndex}`,
        );
    }
    if (payload.ballotCount !== ballots.aggregate.ballotCount) {
        throw new InvalidPayloadError(
            `Tally publication ballot count does not match the accepted ballot transcript for option ${optionIndex}`,
        );
    }
    if (decodeScalar(payload.tally, 'Published tally') !== tally) {
        throw new InvalidPayloadError(
            `Tally publication does not match the recomputed tally for option ${optionIndex}`,
        );
    }
    assertUniqueSortedIndices(
        payload.decryptionParticipantIndices,
        'Tally publication decryption participant',
    );

    const actualIndices = decryptionShares
        .map((entry) => entry.share.index)
        .sort((left, right) => left - right);
    if (!sameNumberSet(payload.decryptionParticipantIndices, actualIndices)) {
        throw new InvalidPayloadError(
            `Tally publication decryption participant set does not match the supplied decryption shares for option ${optionIndex}`,
        );
    }
}

/**
 * Verifies published tallies from the signed DKG log, typed ballot payloads,
 * typed decryption-share payloads, and optional tally-publication records.
 *
 * The helper intentionally recomputes everything locally: it verifies the DKG
 * transcript, recomputes one aggregate per option from the accepted ballots,
 * verifies each DLEQ proof against transcript-derived trustee keys, and only
 * then combines shares into the final tallies.
 *
 * @param input Published tally verification input.
 * @returns Fully verified per-option tally results.
 */
export const verifyPublishedVotingResults = async (
    input: VerifyPublishedVotingResultsInput,
): Promise<VerifiedPublishedVotingResults> => {
    const context = await buildVotingManifestContext(
        input.manifest,
        input.sessionId,
    );
    const dkg = await verifyDKGTranscript({
        transcript: input.dkgTranscript,
        manifest: context.manifest,
        sessionId: context.sessionId,
    });
    const auditedBallots = await auditSignedPayloads(input.ballotPayloads);
    const auditedDecryptionShares = await auditSignedPayloads(
        input.decryptionSharePayloads,
    );
    const tallyPublications =
        input.tallyPublications === undefined ||
        input.tallyPublications.length === 0
            ? undefined
            : (await auditSignedPayloads(input.tallyPublications))
                  .acceptedPayloads;
    await auditSignedPayloads([
        ...input.dkgTranscript,
        ...auditedBallots.acceptedPayloads,
        ...auditedDecryptionShares.acceptedPayloads,
        ...(tallyPublications ?? []),
    ]);

    await verifyPayloadsAgainstRegistrations(
        [
            ...auditedBallots.acceptedPayloads,
            ...auditedDecryptionShares.acceptedPayloads,
            ...(tallyPublications ?? []),
        ],
        dkg.registrations,
    );

    const ballots = await verifyBallotSubmissionPayloadsByOption({
        ballotPayloads: auditedBallots.acceptedPayloads,
        publicKey: dkg.derivedPublicKey,
        manifest: context.manifest,
        sessionId: context.sessionId,
    });
    const decryptionShares = await verifyDecryptionSharePayloadsByOption({
        aggregates: ballots.map((optionBallots) => ({
            optionIndex: optionBallots.optionIndex,
            aggregate: optionBallots.aggregate,
        })),
        dkg,
        decryptionSharePayloads: auditedDecryptionShares.acceptedPayloads,
        manifest: context.manifest,
        sessionId: context.sessionId,
    });

    const tallyPublicationMap = new Map<
        number,
        SignedPayload<TallyPublicationPayload>
    >();
    if (tallyPublications !== undefined) {
        if (tallyPublications.length !== context.optionCount) {
            throw new InvalidPayloadError(
                `Expected ${context.optionCount} tally-publication payloads, received ${tallyPublications.length}`,
            );
        }

        for (const signedPayload of tallyPublications) {
            const payload = signedPayload.payload;
            assertPhase(payload, TALLY_PUBLICATION_PHASE, 'Tally publication');
            if (payload.sessionId !== context.sessionId) {
                throw new InvalidPayloadError(
                    'Tally publication session does not match the verification input',
                );
            }
            if (payload.manifestHash !== context.manifestHash) {
                throw new InvalidPayloadError(
                    'Tally publication manifest hash does not match the verification input',
                );
            }
            assertValidOptionIndex(
                payload.optionIndex,
                context.optionCount,
                'Tally publication',
            );
            if (tallyPublicationMap.has(payload.optionIndex)) {
                throw new InvalidPayloadError(
                    `Duplicate tally publication for option ${payload.optionIndex} is not allowed`,
                );
            }
            tallyPublicationMap.set(payload.optionIndex, signedPayload);
        }
    }

    const results: VerifiedPublishedOptionVotingResult[] = [];
    for (
        let optionIndex = 1;
        optionIndex <= context.optionCount;
        optionIndex += 1
    ) {
        const optionBallots = ballots.find(
            (entry) => entry.optionIndex === optionIndex,
        );
        const optionDecryptionShares = decryptionShares.find(
            (entry) => entry.optionIndex === optionIndex,
        );

        if (optionBallots === undefined) {
            throw new InvalidPayloadError(
                `Missing verified ballots for option ${optionIndex}`,
            );
        }
        if (optionDecryptionShares === undefined) {
            throw new InvalidPayloadError(
                `Missing verified decryption shares for option ${optionIndex}`,
            );
        }

        const tally = recomputePublishedTally(
            optionBallots,
            optionDecryptionShares.decryptionShares,
        );
        const publication = tallyPublicationMap.get(optionIndex);

        if (tallyPublications !== undefined && publication === undefined) {
            throw new InvalidPayloadError(
                `Missing tally publication for option ${optionIndex}`,
            );
        }
        if (publication !== undefined) {
            verifyPublishedTallyPayload(
                publication.payload,
                optionIndex,
                optionBallots,
                optionDecryptionShares.decryptionShares,
                tally,
            );
        }

        results.push({
            optionIndex,
            ballots: optionBallots,
            decryptionShares: optionDecryptionShares.decryptionShares,
            tally,
        });
    }

    return {
        dkg,
        options: results,
    };
};

/**
 * Verifies one published tally from the signed DKG log, typed ballot payloads,
 * typed decryption-share payloads, and an optional tally-publication record for
 * a single-option manifest.
 *
 * @param input Published tally verification input.
 * @returns Fully verified tally result.
 */
export const verifyPublishedVotingResult = async (
    input: VerifyPublishedVotingResultInput,
): Promise<VerifiedPublishedVotingResult> => {
    const context = await buildVotingManifestContext(
        input.manifest,
        input.sessionId,
    );
    assertSingleOptionManifest(context.manifest, 'verifyPublishedVotingResult');

    const results = await verifyPublishedVotingResults({
        manifest: context.manifest,
        sessionId: context.sessionId,
        dkgTranscript: input.dkgTranscript,
        ballotPayloads: input.ballotPayloads,
        decryptionSharePayloads: input.decryptionSharePayloads,
        tallyPublications:
            input.tallyPublication === undefined
                ? undefined
                : [input.tallyPublication],
    });
    const option = results.options[0];

    return {
        dkg: results.dkg,
        ballots: option.ballots,
        decryptionShares: option.decryptionShares,
        tally: option.tally,
    };
};
