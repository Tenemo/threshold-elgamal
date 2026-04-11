import { InvalidPayloadError } from '../core/index.js';
import { decodeScalar } from '../core/ristretto.js';
import {
    verifyDKGTranscript,
    type VerifiedDKGTranscript,
} from '../dkg/verification.js';
import { combineDecryptionShares } from '../threshold/index.js';

import { verifyBallotClosePayload } from './ballot-close.js';
import type { VerifiedOptionBallotAggregation } from './ballots.js';
import { auditSignedPayloads, type BoardAudit } from './board-audit.js';
import type {
    BallotClosePayload,
    BallotSubmissionPayload,
    DecryptionSharePayload,
    ElectionManifest,
    SignedPayload,
    TallyPublicationPayload,
} from './types.js';
import { verifyBallotSubmissionPayloadsByOption } from './voting-ballots.js';
import { verifyDecryptionSharePayloadsByOption } from './voting-decryption.js';
import {
    assertPhase,
    assertUniqueSortedIndices,
    assertValidOptionIndex,
    buildVotingManifestContext,
    sameNumberSet,
    TALLY_PUBLICATION_PHASE,
    verifyPayloadsAgainstRegistrations,
} from './voting-shared.js';
import type {
    VerifiedDecryptionSharePayload,
    VerifiedOptionDecryptionShares,
    VerifiedPublishedOptionVotingResult,
    VerifyPublishedVotingResultsInput,
} from './voting-types.js';

/** Stable high-level failure codes for full ceremony verification. */
export type ElectionVerificationErrorCode =
    | 'MANIFEST_INVALID'
    | 'BOARD_INVALID'
    | 'DKG_INVALID'
    | 'SIGNATURE_INVALID'
    | 'BALLOT_INVALID'
    | 'DECRYPTION_INVALID'
    | 'TALLY_INVALID';

/** Named verification stage used by the high-level ceremony verifier. */
export type ElectionVerificationStage =
    | 'manifest'
    | 'board'
    | 'dkg'
    | 'signatures'
    | 'ballots'
    | 'decryption'
    | 'tally';

/** Stable structured failure result returned by the non-throwing verifier. */
export type ElectionVerificationFailure = {
    readonly code: ElectionVerificationErrorCode;
    readonly stage: ElectionVerificationStage;
    readonly reason: string;
};

/** Error raised when full ceremony verification fails at a named stage. */
class ElectionVerificationError extends InvalidPayloadError {
    public readonly code: ElectionVerificationErrorCode;
    public readonly stage: ElectionVerificationStage;
    public readonly reason: string;

    public constructor(
        code: ElectionVerificationErrorCode,
        stage: ElectionVerificationStage,
        message: string,
    ) {
        super(message);
        this.code = code;
        this.stage = stage;
        this.reason = message;
    }
}

/** Detailed successful output from full ceremony verification. */
export type VerifiedElectionCeremonyDetailed = {
    readonly manifest: ElectionManifest;
    readonly manifestHash: string;
    readonly sessionId: string;
    readonly qual: readonly number[];
    readonly countedParticipantIndices: readonly number[];
    readonly excludedParticipantIndices: readonly number[];
    readonly perOptionAcceptedCounts: readonly {
        readonly optionIndex: number;
        readonly acceptedCount: number;
    }[];
    readonly perOptionTallies: readonly {
        readonly optionIndex: number;
        readonly tally: bigint;
    }[];
    readonly boardAudit: {
        readonly dkg: BoardAudit;
        readonly ballots: BoardAudit<BallotSubmissionPayload>;
        readonly ballotClose: BoardAudit<BallotClosePayload>;
        readonly decryptionShares: BoardAudit<DecryptionSharePayload>;
        readonly tallyPublications?: BoardAudit<TallyPublicationPayload>;
        readonly overall: BoardAudit;
    };
    readonly dkg: VerifiedDKGTranscript;
    readonly options: readonly VerifiedPublishedOptionVotingResult[];
};

/** Input bundle for full ceremony verification across all published options. */
export type VerifyElectionCeremonyDetailedInput =
    VerifyPublishedVotingResultsInput;

/** Non-throwing result shape for full ceremony verification. */
export type ElectionVerificationResult =
    | {
          readonly ok: true;
          readonly verified: VerifiedElectionCeremonyDetailed;
      }
    | {
          readonly ok: false;
          readonly error: ElectionVerificationFailure;
      };

const wrapStageError = (
    code: ElectionVerificationErrorCode,
    stage: ElectionVerificationStage,
    error: unknown,
): never => {
    if (error instanceof ElectionVerificationError) {
        throw error;
    }

    throw new ElectionVerificationError(
        code,
        stage,
        error instanceof Error ? error.message : String(error),
    );
};

const recomputePublishedTally = (
    ballots: VerifiedOptionBallotAggregation,
    decryptionShares: readonly VerifiedDecryptionSharePayload[],
): bigint =>
    combineDecryptionShares(
        ballots.aggregate.ciphertext,
        decryptionShares.map((entry) => entry.share),
        BigInt(ballots.aggregate.ballotCount) * 10n,
    );

const verifyPublishedTallyPayload = (
    payload: TallyPublicationPayload,
    optionIndex: number,
    ballots: VerifiedOptionBallotAggregation,
    decryptionShares: readonly VerifiedDecryptionSharePayload[],
    tally: bigint,
): void => {
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
};

const findOptionDecryptionShares = (
    decryptionShares: readonly VerifiedOptionDecryptionShares[],
    optionIndex: number,
): readonly VerifiedDecryptionSharePayload[] => {
    const entry = decryptionShares.find(
        (candidate) => candidate.optionIndex === optionIndex,
    );

    if (entry === undefined) {
        throw new InvalidPayloadError(
            `Missing verified decryption shares for option ${optionIndex}`,
        );
    }

    return entry.decryptionShares;
};

/**
 * Replays the published ceremony from manifest to tally, including board audit,
 * DKG verification, ballot verification, decryption-share verification, and
 * per-option tally checks.
 *
 * @param input Full public ceremony input bundle.
 * @returns Detailed verified ceremony output.
 */
export const verifyElectionCeremonyDetailed = async (
    input: VerifyElectionCeremonyDetailedInput,
): Promise<VerifiedElectionCeremonyDetailed> => {
    let context!: Awaited<ReturnType<typeof buildVotingManifestContext>>;
    try {
        context = await buildVotingManifestContext(
            input.manifest,
            input.sessionId,
        );
    } catch (error) {
        wrapStageError('MANIFEST_INVALID', 'manifest', error);
    }

    let dkgAudit!: BoardAudit;
    let ballotAudit!: BoardAudit<BallotSubmissionPayload>;
    let ballotCloseAudit!: BoardAudit<BallotClosePayload>;
    let decryptionAudit!: BoardAudit<DecryptionSharePayload>;
    let tallyAudit: BoardAudit<TallyPublicationPayload> | undefined;
    let overallAudit!: BoardAudit;
    try {
        dkgAudit = await auditSignedPayloads(input.dkgTranscript);
        ballotAudit = await auditSignedPayloads(input.ballotPayloads);
        ballotCloseAudit = await auditSignedPayloads([
            input.ballotClosePayload,
        ]);
        decryptionAudit = await auditSignedPayloads(
            input.decryptionSharePayloads,
        );
        tallyAudit =
            input.tallyPublications === undefined ||
            input.tallyPublications.length === 0
                ? undefined
                : await auditSignedPayloads(input.tallyPublications);
        overallAudit = await auditSignedPayloads([
            ...dkgAudit.acceptedPayloads,
            ...ballotAudit.acceptedPayloads,
            ...ballotCloseAudit.acceptedPayloads,
            ...decryptionAudit.acceptedPayloads,
            ...(tallyAudit?.acceptedPayloads ?? []),
        ]);
    } catch (error) {
        wrapStageError('BOARD_INVALID', 'board', error);
    }

    let dkg!: VerifiedDKGTranscript;
    try {
        dkg = await verifyDKGTranscript({
            transcript: dkgAudit.acceptedPayloads,
            manifest: context.manifest,
            sessionId: context.sessionId,
        });
    } catch (error) {
        wrapStageError('DKG_INVALID', 'dkg', error);
    }

    try {
        await verifyPayloadsAgainstRegistrations(
            [
                ...ballotAudit.acceptedPayloads,
                ...ballotCloseAudit.acceptedPayloads,
                ...decryptionAudit.acceptedPayloads,
                ...(tallyAudit?.acceptedPayloads ?? []),
            ],
            dkg.registrations,
        );
    } catch (error) {
        wrapStageError('SIGNATURE_INVALID', 'signatures', error);
    }

    let ballotClose!: ReturnType<typeof verifyBallotClosePayload>;
    try {
        if (ballotCloseAudit.acceptedPayloads.length !== 1) {
            throw new InvalidPayloadError(
                'Ballot close requires exactly one payload',
            );
        }

        ballotClose = verifyBallotClosePayload({
            ballotClosePayload: ballotCloseAudit.acceptedPayloads[0],
            ballotPayloads: ballotAudit.acceptedPayloads,
            manifestHash: context.manifestHash,
            optionCount: context.optionCount,
            organizerIndex: dkg.organizerIndex,
            participantCount: dkg.participantCount,
            sessionId: context.sessionId,
            threshold: dkg.threshold,
        });
    } catch (error) {
        wrapStageError('BALLOT_INVALID', 'ballots', error);
    }

    let ballots!: readonly VerifiedOptionBallotAggregation[];
    try {
        ballots = await verifyBallotSubmissionPayloadsByOption({
            ballotPayloads: ballotClose.countedBallotPayloads,
            publicKey: dkg.derivedPublicKey,
            manifest: context.manifest,
            sessionId: context.sessionId,
        });
    } catch (error) {
        wrapStageError('BALLOT_INVALID', 'ballots', error);
    }

    let decryptionShares!: readonly VerifiedOptionDecryptionShares[];
    try {
        decryptionShares = await verifyDecryptionSharePayloadsByOption({
            aggregates: ballots.map((optionBallots) => ({
                optionIndex: optionBallots.optionIndex,
                aggregate: optionBallots.aggregate,
            })),
            dkg,
            decryptionSharePayloads: decryptionAudit.acceptedPayloads,
            manifest: context.manifest,
            sessionId: context.sessionId,
        });
    } catch (error) {
        wrapStageError('DECRYPTION_INVALID', 'decryption', error);
    }

    const tallyPublicationMap = new Map<
        number,
        SignedPayload<TallyPublicationPayload>
    >();
    try {
        if (tallyAudit !== undefined) {
            if (tallyAudit.acceptedPayloads.length !== context.optionCount) {
                throw new InvalidPayloadError(
                    `Expected ${context.optionCount} tally-publication payloads, received ${tallyAudit.acceptedPayloads.length}`,
                );
            }

            for (const signedPayload of tallyAudit.acceptedPayloads) {
                const payload = signedPayload.payload;
                assertPhase(
                    payload,
                    TALLY_PUBLICATION_PHASE,
                    'Tally publication',
                );
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
    } catch (error) {
        wrapStageError('TALLY_INVALID', 'tally', error);
    }

    let options!: VerifiedPublishedOptionVotingResult[];
    try {
        options = [];
        for (
            let optionIndex = 1;
            optionIndex <= context.optionCount;
            optionIndex += 1
        ) {
            const optionBallots = ballots.find(
                (entry) => entry.optionIndex === optionIndex,
            );
            if (optionBallots === undefined) {
                throw new InvalidPayloadError(
                    `Missing verified ballots for option ${optionIndex}`,
                );
            }

            const optionDecryptionShares = findOptionDecryptionShares(
                decryptionShares,
                optionIndex,
            );
            const tally = recomputePublishedTally(
                optionBallots,
                optionDecryptionShares,
            );
            const publication = tallyPublicationMap.get(optionIndex);

            if (tallyAudit !== undefined && publication === undefined) {
                throw new InvalidPayloadError(
                    `Missing tally publication for option ${optionIndex}`,
                );
            }
            if (publication !== undefined) {
                verifyPublishedTallyPayload(
                    publication.payload,
                    optionIndex,
                    optionBallots,
                    optionDecryptionShares,
                    tally,
                );
            }

            options.push({
                optionIndex,
                ballots: optionBallots,
                decryptionShares: optionDecryptionShares,
                tally,
            });
        }
    } catch (error) {
        wrapStageError('TALLY_INVALID', 'tally', error);
    }

    return {
        manifest: context.manifest,
        manifestHash: context.manifestHash,
        sessionId: context.sessionId,
        qual: dkg.qual,
        countedParticipantIndices: ballotClose.countedParticipantIndices,
        excludedParticipantIndices: ballotClose.excludedParticipantIndices,
        perOptionAcceptedCounts: options.map((option) => ({
            optionIndex: option.optionIndex,
            acceptedCount: option.ballots.aggregate.ballotCount,
        })),
        perOptionTallies: options.map((option) => ({
            optionIndex: option.optionIndex,
            tally: option.tally,
        })),
        boardAudit: {
            dkg: dkgAudit,
            ballots: ballotAudit,
            ballotClose: ballotCloseAudit,
            decryptionShares: decryptionAudit,
            tallyPublications: tallyAudit,
            overall: overallAudit,
        },
        dkg,
        options,
    };
};

/**
 * Runs the full ceremony verifier and returns a structured success-or-failure
 * result without throwing.
 *
 * @param input Full public ceremony input bundle.
 * @returns Verified ceremony output or a stable structured failure.
 */
export const verifyElectionCeremonyDetailedResult = async (
    input: VerifyElectionCeremonyDetailedInput,
): Promise<ElectionVerificationResult> => {
    try {
        return {
            ok: true,
            verified: await verifyElectionCeremonyDetailed(input),
        };
    } catch (error) {
        if (error instanceof ElectionVerificationError) {
            return {
                ok: false,
                error: {
                    code: error.code,
                    stage: error.stage,
                    reason: error.reason,
                },
            };
        }

        return {
            ok: false,
            error: {
                code: 'MANIFEST_INVALID',
                stage: 'manifest',
                reason: error instanceof Error ? error.message : String(error),
            },
        };
    }
};
