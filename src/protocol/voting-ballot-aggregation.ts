import { bytesToHex } from '../core/bytes';
import {
    InvalidPayloadError,
    RISTRETTO_GROUP,
    assertInSubgroup,
    sha256,
    utf8ToBytes,
    type EncodedPoint,
} from '../core/index';
import { encodePoint, RISTRETTO_ZERO } from '../core/ristretto';
import { addEncryptedValues } from '../elgamal/additive';
import type { ElGamalCiphertext } from '../elgamal/types';
import { verifyDisjunctiveProof } from '../proofs/disjunctive';
import type { DisjunctiveProof, ProofContext } from '../proofs/types';
import { createVerifiedAggregateCiphertext } from '../threshold/types';
import type { VerifiedAggregateCiphertext } from '../threshold/types';

import { canonicalizeJson } from './canonical-json';

const assertPositiveInteger = (value: number, label: string): void => {
    if (!Number.isInteger(value) || value < 1) {
        throw new InvalidPayloadError(`${label} must be a positive integer`);
    }
};

const compareBallotEntries = (
    left: BallotTranscriptEntry,
    right: BallotTranscriptEntry,
): number => {
    if (left.voterIndex !== right.voterIndex) {
        return left.voterIndex - right.voterIndex;
    }

    return left.optionIndex - right.optionIndex;
};

/** Verified additive ballot record used in transcript aggregation. */
export type BallotTranscriptEntry = {
    readonly voterIndex: number;
    readonly optionIndex: number;
    readonly ciphertext: ElGamalCiphertext;
    readonly proof: DisjunctiveProof;
};

/** Result of verifying and aggregating a ballot transcript. */
export type VerifiedBallotAggregation = {
    readonly aggregate: VerifiedAggregateCiphertext;
    readonly ballots: readonly BallotTranscriptEntry[];
    readonly transcriptHash: string;
};

/** Verified additive ballot aggregation for one manifest option slot. */
export type VerifiedOptionBallotAggregation = VerifiedBallotAggregation & {
    readonly optionIndex: number;
};

/** Grouped view of one accepted voter's ballot across all option slots. */
type VoterBallot = {
    readonly voterIndex: number;
    readonly ballots: readonly BallotTranscriptEntry[];
};

/** Input bundle for ballot verification and aggregation. */
type VerifyAndAggregateBallotsInput = {
    readonly ballots: readonly BallotTranscriptEntry[];
    readonly publicKey: EncodedPoint;
    readonly validValues: readonly bigint[];
    readonly protocolVersion: string;
    readonly manifestHash: string;
    readonly sessionId: string;
    readonly label?: string;
};

/** Input bundle for per-option ballot verification and aggregation. */
type VerifyAndAggregateBallotsByOptionInput = VerifyAndAggregateBallotsInput & {
    readonly optionCount: number;
};

const canonicalBallotJson = (
    ballots: readonly BallotTranscriptEntry[],
): string =>
    canonicalizeJson(
        [...ballots].sort(compareBallotEntries).map((ballot) => ({
            voterIndex: ballot.voterIndex,
            optionIndex: ballot.optionIndex,
            ciphertext: ballot.ciphertext,
            proof: ballot.proof,
        })),
        {
            bigintByteLength: RISTRETTO_GROUP.byteLength,
        },
    );

const buildProofContext = (
    ballot: BallotTranscriptEntry,
    input: VerifyAndAggregateBallotsInput,
): ProofContext => ({
    protocolVersion: input.protocolVersion,
    suiteId: RISTRETTO_GROUP.name,
    manifestHash: input.manifestHash,
    sessionId: input.sessionId,
    label: input.label ?? 'ballot-range-proof',
    voterIndex: ballot.voterIndex,
    optionIndex: ballot.optionIndex,
});

const groupBallotsByVoter = (
    ballots: readonly BallotTranscriptEntry[],
    optionCount: number,
): readonly VoterBallot[] => {
    const sortedBallots = [...ballots].sort(compareBallotEntries);
    const seenSlots = new Set<string>();
    const byVoter = new Map<number, Map<number, BallotTranscriptEntry>>();

    for (const ballot of sortedBallots) {
        assertPositiveInteger(ballot.voterIndex, 'Ballot voter index');
        assertPositiveInteger(ballot.optionIndex, 'Ballot option index');

        if (ballot.optionIndex > optionCount) {
            throw new InvalidPayloadError(
                `Ballot option index ${ballot.optionIndex} exceeds the manifest option count ${optionCount}`,
            );
        }

        const slotKey = `${ballot.voterIndex}:${ballot.optionIndex}`;
        if (seenSlots.has(slotKey)) {
            throw new InvalidPayloadError(
                `Duplicate ballot slot ${slotKey} is not allowed`,
            );
        }
        seenSlots.add(slotKey);

        const voterBallots =
            byVoter.get(ballot.voterIndex) ??
            new Map<number, BallotTranscriptEntry>();
        voterBallots.set(ballot.optionIndex, ballot);
        byVoter.set(ballot.voterIndex, voterBallots);
    }

    return [...byVoter.entries()]
        .sort(([left], [right]) => left - right)
        .map(([voterIndex, optionMap]) => {
            const groupedBallots: BallotTranscriptEntry[] = [];

            for (
                let optionIndex = 1;
                optionIndex <= optionCount;
                optionIndex += 1
            ) {
                const ballot = optionMap.get(optionIndex);
                if (ballot === undefined) {
                    throw new InvalidPayloadError(
                        `Accepted voter ${voterIndex} must submit exactly one ballot for every option slot`,
                    );
                }
                groupedBallots.push(ballot);
            }

            return {
                voterIndex,
                ballots: groupedBallots,
            };
        });
};

/**
 * Hashes the accepted ballot transcript deterministically.
 *
 * @param ballots Verified ballot records.
 * @returns Lowercase hexadecimal transcript hash.
 */
const hashAcceptedBallots = async (
    ballots: readonly BallotTranscriptEntry[],
): Promise<string> =>
    bytesToHex(await sha256(utf8ToBytes(canonicalBallotJson(ballots))));

/**
 * Verifies disjunctive ballot proofs, rejects duplicate ballot slots, and
 * recomputes the additive aggregate deterministically.
 *
 * @param input Ballot transcript verification input.
 * @returns Verified aggregate and sorted accepted ballots.
 */
export const verifyAndAggregateBallots = async (
    input: VerifyAndAggregateBallotsInput,
): Promise<VerifiedBallotAggregation> => {
    assertInSubgroup(input.publicKey);

    const sortedBallots = [...input.ballots].sort(compareBallotEntries);
    const seenSlots = new Set<string>();

    for (const ballot of sortedBallots) {
        assertPositiveInteger(ballot.voterIndex, 'Ballot voter index');
        assertPositiveInteger(ballot.optionIndex, 'Ballot option index');

        const slotKey = `${ballot.voterIndex}:${ballot.optionIndex}`;
        if (seenSlots.has(slotKey)) {
            throw new InvalidPayloadError(
                `Duplicate ballot slot ${slotKey} is not allowed`,
            );
        }
        seenSlots.add(slotKey);

        const proofContext = buildProofContext(ballot, input);
        const valid = await verifyDisjunctiveProof(
            ballot.proof,
            ballot.ciphertext,
            input.publicKey,
            input.validValues,
            RISTRETTO_GROUP,
            proofContext,
        );
        if (!valid) {
            throw new InvalidPayloadError(
                `Ballot proof failed verification for voter ${ballot.voterIndex} option ${ballot.optionIndex}`,
            );
        }
    }

    const ciphertext = sortedBallots.reduce(
        (aggregate, ballot) => addEncryptedValues(aggregate, ballot.ciphertext),
        {
            c1: encodePoint(RISTRETTO_ZERO),
            c2: encodePoint(RISTRETTO_ZERO),
        } satisfies ElGamalCiphertext,
    );
    const transcriptHash = await hashAcceptedBallots(sortedBallots);
    const aggregate = createVerifiedAggregateCiphertext(
        transcriptHash,
        ciphertext,
        sortedBallots.length,
    );

    return {
        aggregate,
        ballots: sortedBallots,
        transcriptHash,
    };
};

/**
 * Verifies typed ballots for every manifest option and recomputes one additive
 * aggregate per option slot.
 *
 * @param input Ballot transcript verification input.
 * @returns Ordered per-option verified aggregates.
 */
export const verifyAndAggregateBallotsByOption = async (
    input: VerifyAndAggregateBallotsByOptionInput,
): Promise<readonly VerifiedOptionBallotAggregation[]> => {
    if (!Number.isInteger(input.optionCount) || input.optionCount < 1) {
        throw new InvalidPayloadError('optionCount must be a positive integer');
    }

    const groupedVoterBallots = groupBallotsByVoter(
        input.ballots,
        input.optionCount,
    );

    const aggregations: VerifiedOptionBallotAggregation[] = [];
    for (
        let optionIndex = 1;
        optionIndex <= input.optionCount;
        optionIndex += 1
    ) {
        const ballots = groupedVoterBallots.map(
            (voterBallot) => voterBallot.ballots[optionIndex - 1],
        );
        let aggregation: VerifiedBallotAggregation;
        try {
            aggregation = await verifyAndAggregateBallots({
                ...input,
                ballots,
            });
        } catch (error) {
            if (input.optionCount === 1) {
                throw error;
            }

            const message =
                error instanceof Error ? error.message : String(error);
            throw new InvalidPayloadError(
                `Option ${optionIndex} ballot verification failed: ${message}`,
            );
        }

        aggregations.push({
            ...aggregation,
            optionIndex,
        });
    }

    return aggregations;
};
