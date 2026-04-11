import { assertCanonicalRistrettoGroup } from '../core/group-invariants.js';
import {
    assertPositiveParticipantIndex,
    modQ,
    type CryptoGroup,
} from '../core/index.js';
import {
    decodePoint,
    encodePoint,
    pointAdd,
    pointMultiply,
    RISTRETTO_ZERO,
} from '../core/ristretto.js';
import type { EncodedPoint } from '../core/types.js';
import type { ComplaintPayload } from '../protocol/types.js';

const deriveTranscriptVerificationKeyInternal = (
    commitmentSets: readonly (readonly EncodedPoint[])[],
    participantIndex: number,
    group: CryptoGroup,
): EncodedPoint => {
    assertCanonicalRistrettoGroup(
        group,
        'Transcript verification-key derivation group',
    );
    assertPositiveParticipantIndex(participantIndex);
    const point = BigInt(participantIndex);

    return encodePoint(
        commitmentSets.reduce((outerAccumulator, commitments) => {
            let innerAccumulator = RISTRETTO_ZERO;
            let exponent = 1n;

            for (const commitment of commitments) {
                innerAccumulator = pointAdd(
                    innerAccumulator,
                    pointMultiply(
                        decodePoint(commitment, 'Feldman commitment'),
                        exponent,
                    ),
                );
                exponent = modQ(exponent * point, group.q);
            }

            return pointAdd(outerAccumulator, innerAccumulator);
        }, RISTRETTO_ZERO),
    );
};

/**
 * Derives the transcript verification key `Y_j` for one participant index from
 * published Feldman commitments.
 *
 * @param feldmanCommitments Qualified dealer commitment vectors.
 * @param participantIndex Participant index whose key will be derived.
 * @param group Selected group.
 * @returns Transcript-derived verification key `Y_j`.
 */
export const deriveTranscriptVerificationKey = (
    feldmanCommitments: readonly {
        readonly dealerIndex: number;
        readonly commitments: readonly EncodedPoint[];
    }[],
    participantIndex: number,
    group: CryptoGroup,
): EncodedPoint =>
    deriveTranscriptVerificationKeyInternal(
        feldmanCommitments.map((entry) => entry.commitments),
        participantIndex,
        group,
    );

/**
 * Derives the qualified joint public key from the constant Feldman
 * commitments.
 *
 * @param feldmanCommitments Qualified dealer commitment vectors.
 * @param group Selected group.
 * @returns Derived joint public key.
 */
export const deriveJointPublicKey = (
    feldmanCommitments: readonly {
        readonly dealerIndex: number;
        readonly commitments: readonly EncodedPoint[];
    }[],
    group: CryptoGroup,
): EncodedPoint => {
    assertCanonicalRistrettoGroup(group, 'Joint public-key derivation group');

    return encodePoint(
        feldmanCommitments.reduce(
            (sum, entry) =>
                pointAdd(
                    sum,
                    decodePoint(entry.commitments[0], 'Constant commitment'),
                ),
            RISTRETTO_ZERO,
        ),
    );
};

/**
 * Derives the qualified participant set from accepted complaint outcomes.
 *
 * @param participantCount Total participant count.
 * @param acceptedComplaints Complaint set resolved in the dealer-fault branch.
 * @returns Qualified participant indices.
 */
export const deriveQualifiedParticipantIndices = (
    participantCount: number,
    acceptedComplaints: readonly ComplaintPayload[],
): readonly number[] => {
    const disqualifiedDealers = new Set(
        acceptedComplaints.map((complaint) => complaint.dealerIndex),
    );

    return Array.from(
        { length: participantCount },
        (_value, index) => index + 1,
    ).filter((index) => !disqualifiedDealers.has(index));
};
