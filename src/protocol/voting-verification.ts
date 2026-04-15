/**
 * Top-level full-ceremony verification for the supported voting workflow.
 *
 * This module is the shortest path for auditors and bulletin-board readers who
 * want one call that replays manifest validation, board audit, DKG, ballots,
 * decryption shares, and tally checks.
 */
import { InvalidPayloadError } from '../core/index';
import { decodeScalar } from '../core/ristretto';
import {
    verifyDKGTranscript,
    type VerifiedDKGTranscript,
} from '../dkg/verification';
import {
    combineDecryptionShares,
    prepareAggregateForDecryption,
} from '../threshold/decrypt';

import { auditSignedPayloads, type BoardAudit } from './board-audit';
import type {
    BallotClosePayload,
    BallotSubmissionPayload,
    DecryptionSharePayload,
    ElectionManifest,
    VerifyElectionCeremonyInput,
    VerifiedDecryptionSharePayload,
    VerifiedOptionDecryptionShares,
    VerifiedPublishedOptionVotingResult,
    SignedPayload,
    TallyPublicationPayload,
} from './types';
import type { VerifiedOptionBallotAggregation } from './voting-ballot-aggregation';
import { verifyBallotSubmissionPayloadsByOption } from './voting-ballots';
import { verifyDecryptionSharePayloadsByOption } from './voting-decryption';
import {
    assertPhase,
    assertUniqueSortedIndices,
    assertValidOptionIndex,
    BALLOT_CLOSE_PHASE,
    buildVotingManifestContext,
    sameNumberSet,
    TALLY_PUBLICATION_PHASE,
    verifyPayloadsAgainstRegistrations,
} from './voting-shared';

/**
 * Stable high-level failure codes for full ceremony verification.
 *
 * Applications can key off these codes instead of parsing free-form error
 * strings.
 */
export type ElectionVerificationErrorCode =
    | 'MANIFEST_INVALID'
    | 'BOARD_INVALID'
    | 'DKG_INVALID'
    | 'SIGNATURE_INVALID'
    | 'BALLOT_INVALID'
    | 'DECRYPTION_INVALID'
    | 'TALLY_INVALID';

/**
 * Named verification stage used by the high-level ceremony verifier.
 */
export type ElectionVerificationStage =
    | 'manifest'
    | 'board'
    | 'dkg'
    | 'signatures'
    | 'ballots'
    | 'decryption'
    | 'tally';

/**
 * Stable structured failure result returned by the non-throwing verifier.
 */
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

/**
 * Detailed successful output from full ceremony verification.
 *
 * This bundles the derived DKG material, accepted ballot set, per-option
 * tallies, and deterministic board-audit output.
 */
export type VerifiedElectionCeremony = {
    readonly manifest: ElectionManifest;
    readonly manifestHash: string;
    readonly sessionId: string;
    readonly qualifiedParticipantIndices: readonly number[];
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

/**
 * Non-throwing result shape for full ceremony verification.
 *
 * Most application integrations should prefer this over exceptions.
 */
export type ElectionVerificationResult =
    | {
          readonly ok: true;
          readonly verified: VerifiedElectionCeremony;
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

const recomputePublishedTally = (input: {
    readonly ballots: VerifiedOptionBallotAggregation;
    readonly decryptionShares: readonly VerifiedDecryptionSharePayload[];
    readonly jointPublicKey: VerifiedDKGTranscript['jointPublicKey'];
    readonly protocolVersion: string;
    readonly manifestHash: string;
    readonly sessionId: string;
}): bigint => {
    const preparedAggregate = prepareAggregateForDecryption({
        aggregate: input.ballots.aggregate,
        publicKey: input.jointPublicKey,
        protocolVersion: input.protocolVersion,
        manifestHash: input.manifestHash,
        sessionId: input.sessionId,
        optionIndex: input.ballots.optionIndex,
    });

    return combineDecryptionShares(
        preparedAggregate.ciphertext,
        input.decryptionShares.map((entry) => entry.share),
        BigInt(input.ballots.aggregate.ballotCount) * 10n,
    );
};

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
 * Verified organizer-selected ballot cutoff and the counted ballot subset.
 */
type VerifiedBallotClose = {
    readonly countedBallotPayloads: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly countedParticipantIndices: readonly number[];
    readonly excludedParticipantIndices: readonly number[];
    readonly payload: SignedPayload<BallotClosePayload>;
};

const completeBallotParticipants = (
    ballotPayloads: readonly SignedPayload<BallotSubmissionPayload>[],
    optionCount: number,
): readonly number[] => {
    const participantOptions = new Map<number, Set<number>>();

    for (const signedPayload of ballotPayloads) {
        const payload = signedPayload.payload;
        assertValidOptionIndex(
            payload.optionIndex,
            optionCount,
            'Ballot submission',
        );

        const options =
            participantOptions.get(payload.participantIndex) ??
            new Set<number>();
        options.add(payload.optionIndex);
        participantOptions.set(payload.participantIndex, options);
    }

    return [...participantOptions.entries()]
        .filter(([, options]) => options.size === optionCount)
        .map(([participantIndex]) => participantIndex)
        .sort((left, right) => left - right);
};

/**
 * Verifies the organizer-signed ballot cutoff and extracts the counted ballot
 * subset used for all later decryption and tally verification.
 */
const verifyBallotClosePayload = (input: {
    readonly ballotClosePayload: SignedPayload<BallotClosePayload>;
    readonly ballotPayloads: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly manifestHash: string;
    readonly optionCount: number;
    readonly organizerIndex: number;
    readonly participantCount: number;
    readonly sessionId: string;
    readonly threshold: number;
}): VerifiedBallotClose => {
    const closePayload = input.ballotClosePayload;
    if (closePayload.payload.messageType !== 'ballot-close') {
        throw new InvalidPayloadError(
            'Ballot close verification only accepts ballot-close payloads',
        );
    }
    const payload = closePayload.payload;

    assertPhase(payload, BALLOT_CLOSE_PHASE, 'Ballot close');
    if (payload.sessionId !== input.sessionId) {
        throw new InvalidPayloadError(
            'Ballot close session does not match the verification input',
        );
    }
    if (payload.manifestHash !== input.manifestHash) {
        throw new InvalidPayloadError(
            'Ballot close manifest hash does not match the verification input',
        );
    }
    if (payload.participantIndex !== input.organizerIndex) {
        throw new InvalidPayloadError(
            `Ballot close must be signed by organizer ${input.organizerIndex}`,
        );
    }

    assertUniqueSortedIndices(
        payload.countedParticipantIndices,
        'Ballot close participant',
    );
    for (const participantIndex of payload.countedParticipantIndices) {
        if (participantIndex > input.participantCount) {
            throw new InvalidPayloadError(
                `Ballot close participant ${participantIndex} exceeds the registration roster size ${input.participantCount}`,
            );
        }
    }
    if (payload.countedParticipantIndices.length < input.threshold) {
        throw new InvalidPayloadError(
            `Ballot close must include at least ${input.threshold} participants`,
        );
    }

    const completeParticipants = completeBallotParticipants(
        input.ballotPayloads,
        input.optionCount,
    );
    const completeParticipantSet = new Set(completeParticipants);
    for (const participantIndex of payload.countedParticipantIndices) {
        if (!completeParticipantSet.has(participantIndex)) {
            throw new InvalidPayloadError(
                `Ballot close requires a complete ballot from participant ${participantIndex}`,
            );
        }
    }

    const countedParticipantSet = new Set(payload.countedParticipantIndices);
    const countedBallotPayloads = input.ballotPayloads.filter((signedPayload) =>
        countedParticipantSet.has(signedPayload.payload.participantIndex),
    );
    const excludedParticipantIndices = completeParticipants.filter(
        (participantIndex) => !countedParticipantSet.has(participantIndex),
    );

    return {
        countedBallotPayloads,
        countedParticipantIndices: [...payload.countedParticipantIndices],
        excludedParticipantIndices,
        payload: closePayload,
    };
};

/**
 * Replays the published ceremony from manifest to tally, including board audit,
 * DKG verification, ballot verification, decryption-share verification, and
 * per-option tally checks.
 *
 * This is the main verifier entry point for callers that want failures to
 * abort immediately.
 */
export const verifyElectionCeremony = async (
    input: VerifyElectionCeremonyInput,
): Promise<VerifiedElectionCeremony> => {
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
            publicKey: dkg.jointPublicKey,
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
            const tally = recomputePublishedTally({
                ballots: optionBallots,
                decryptionShares: optionDecryptionShares,
                jointPublicKey: dkg.jointPublicKey,
                protocolVersion: context.protocolVersion,
                manifestHash: context.manifestHash,
                sessionId: context.sessionId,
            });
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
        qualifiedParticipantIndices: dkg.qualifiedParticipantIndices,
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
 * This is the preferred integration point for applications that want stable
 * failure stages and codes instead of exception handling.
 */
export const tryVerifyElectionCeremony = async (
    input: VerifyElectionCeremonyInput,
): Promise<ElectionVerificationResult> => {
    try {
        return {
            ok: true,
            verified: await verifyElectionCeremony(input),
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
