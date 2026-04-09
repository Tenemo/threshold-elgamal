import {
    InvalidPayloadError,
    assertInSubgroup,
    sha256,
    utf8ToBytes,
    type CryptoGroup,
} from '../core/index.js';
import { addEncryptedValues } from '../elgamal/ciphertext.js';
import type { ElgamalCiphertext } from '../elgamal/types.js';
import { verifyDisjunctiveProof } from '../proofs/disjunctive.js';
import type { DisjunctiveProof, ProofContext } from '../proofs/types.js';
import { bytesToHex } from '../serialize/index.js';
import type { VerifiedAggregateCiphertext } from '../threshold/types.js';

import { canonicalizeJson } from './canonical-json.js';

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
    readonly ciphertext: ElgamalCiphertext;
    readonly proof: DisjunctiveProof;
};

/** Result of verifying and aggregating a ballot transcript. */
export type VerifiedBallotAggregation = {
    readonly aggregate: VerifiedAggregateCiphertext;
    readonly ballots: readonly BallotTranscriptEntry[];
    readonly transcriptHash: string;
};

/** Input bundle for ballot verification and aggregation. */
export type VerifyAndAggregateBallotsInput = {
    readonly ballots: readonly BallotTranscriptEntry[];
    readonly publicKey: bigint;
    readonly validValues: readonly bigint[];
    readonly group: CryptoGroup;
    readonly manifestHash: string;
    readonly sessionId: string;
    readonly minimumBallotCount: number;
    readonly label?: string;
};

const canonicalBallotJson = (
    ballots: readonly BallotTranscriptEntry[],
    group: CryptoGroup,
): string =>
    canonicalizeJson(
        [...ballots].sort(compareBallotEntries).map((ballot) => ({
            voterIndex: ballot.voterIndex,
            optionIndex: ballot.optionIndex,
            ciphertext: ballot.ciphertext,
            proof: ballot.proof,
        })),
        {
            bigintByteLength: group.byteLength,
        },
    );

const buildProofContext = (
    ballot: BallotTranscriptEntry,
    input: VerifyAndAggregateBallotsInput,
): ProofContext => ({
    protocolVersion: 'v1',
    suiteId: input.group.name,
    manifestHash: input.manifestHash,
    sessionId: input.sessionId,
    label: input.label ?? 'ballot-range-proof',
    voterIndex: ballot.voterIndex,
    optionIndex: ballot.optionIndex,
});

/**
 * Hashes the accepted ballot transcript deterministically.
 *
 * @param ballots Verified ballot records.
 * @param group Selected group definition.
 * @returns Lowercase hexadecimal transcript hash.
 */
export const hashAcceptedBallots = async (
    ballots: readonly BallotTranscriptEntry[],
    group: CryptoGroup,
): Promise<string> =>
    bytesToHex(await sha256(utf8ToBytes(canonicalBallotJson(ballots, group))));

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
    assertInSubgroup(input.publicKey, input.group.p, input.group.q);

    if (
        !Number.isInteger(input.minimumBallotCount) ||
        input.minimumBallotCount < 1
    ) {
        throw new InvalidPayloadError(
            'minimumBallotCount must be a positive integer',
        );
    }

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
            input.group,
            proofContext,
        );
        if (!valid) {
            throw new InvalidPayloadError(
                `Ballot proof failed verification for voter ${ballot.voterIndex} option ${ballot.optionIndex}`,
            );
        }
    }

    if (sortedBallots.length < input.minimumBallotCount) {
        throw new InvalidPayloadError(
            `Accepted ballot count ${sortedBallots.length} is below the minimum publication threshold ${input.minimumBallotCount}`,
        );
    }

    const ciphertext = sortedBallots.reduce(
        (aggregate, ballot) =>
            addEncryptedValues(aggregate, ballot.ciphertext, input.group.name),
        { c1: 1n, c2: 1n },
    );
    const transcriptHash = await hashAcceptedBallots(
        sortedBallots,
        input.group,
    );
    const aggregate = Object.freeze({
        transcriptHash,
        ciphertext,
        ballotCount: sortedBallots.length,
    }) as VerifiedAggregateCiphertext;

    return {
        aggregate,
        ballots: sortedBallots,
        transcriptHash,
    };
};
