import { InvalidPayloadError, type CryptoGroup } from '../core/index.js';
import { decodeScalar } from '../core/ristretto.js';
import type { EncodedPoint } from '../core/types.js';
import { verifySchnorrProof } from '../proofs/index.js';
import { hashProtocolTranscript } from '../protocol/transcript.js';
import type {
    FeldmanCommitmentPayload,
    KeyDerivationConfirmation,
    SignedPayload,
} from '../protocol/types.js';

import {
    buildSchnorrContext,
    parseCommitmentVector,
} from './verification-shared.js';
import type { ParsedFeldmanCommitment } from './verification-types.js';

export const parseQualifiedFeldmanCommitments = (
    transcript: readonly SignedPayload[],
    qual: readonly number[],
    threshold: number,
    group: CryptoGroup,
): readonly ParsedFeldmanCommitment[] => {
    const feldmanPayloads = transcript.filter(
        (payload): payload is SignedPayload<FeldmanCommitmentPayload> =>
            payload.payload.messageType === 'feldman-commitment',
    );

    return qual.map((participantIndex) => {
        const payload = feldmanPayloads.find(
            (candidate) =>
                candidate.payload.participantIndex === participantIndex,
        );
        if (payload === undefined) {
            throw new InvalidPayloadError(
                `Missing Feldman commitment payload for qualified dealer ${participantIndex}`,
            );
        }

        const commitments = parseCommitmentVector(
            payload.payload.commitments,
            threshold,
            group,
            'Feldman commitment payload',
        );

        if (payload.payload.proofs.length !== commitments.length) {
            throw new InvalidPayloadError(
                `Feldman commitment payload for participant ${participantIndex} must carry one proof per coefficient`,
            );
        }

        const seenCoefficientIndices = new Set<number>();
        commitments.forEach((_commitment, offset) => {
            const proofRecord = payload.payload.proofs[offset];
            if (proofRecord.coefficientIndex !== offset + 1) {
                throw new InvalidPayloadError(
                    `Feldman proof order mismatch for participant ${participantIndex}`,
                );
            }
            if (seenCoefficientIndices.has(proofRecord.coefficientIndex)) {
                throw new InvalidPayloadError(
                    `Duplicate Feldman proof index ${proofRecord.coefficientIndex} for participant ${participantIndex}`,
                );
            }
            seenCoefficientIndices.add(proofRecord.coefficientIndex);
        });

        return {
            dealerIndex: participantIndex,
            commitments,
            payload: payload.payload,
        };
    });
};

export const verifyFeldmanProofs = async (
    feldmanCommitments: readonly ParsedFeldmanCommitment[],
    group: CryptoGroup,
): Promise<void> => {
    for (const entry of feldmanCommitments) {
        for (const [offset, commitment] of entry.commitments.entries()) {
            const proof = entry.payload.proofs[offset];
            const valid = await verifySchnorrProof(
                {
                    challenge: decodeScalar(
                        proof.challenge,
                        'Schnorr challenge',
                    ),
                    response: decodeScalar(proof.response, 'Schnorr response'),
                },
                commitment,
                group,
                buildSchnorrContext(entry.payload, offset + 1, group),
            );
            if (!valid) {
                throw new InvalidPayloadError(
                    `Feldman Schnorr proof failed verification for participant ${entry.dealerIndex} coefficient ${offset + 1}`,
                );
            }
        }
    }
};

export const verifyKeyDerivationConfirmations = async (
    transcript: readonly SignedPayload[],
    qual: readonly number[],
    derivedPublicKey: EncodedPoint,
    group: CryptoGroup,
    minimumConfirmations = qual.length,
): Promise<string> => {
    const qualSet = new Set(qual);
    const preConfirmationTranscript = transcript.filter(
        (payload) =>
            payload.payload.messageType !== 'key-derivation-confirmation',
    );
    const qualHash = await hashProtocolTranscript(
        preConfirmationTranscript.map((payload) => payload.payload),
        group.byteLength,
    );
    const confirmations = transcript.filter(
        (payload): payload is SignedPayload<KeyDerivationConfirmation> =>
            payload.payload.messageType === 'key-derivation-confirmation',
    );

    if (confirmations.length < minimumConfirmations) {
        throw new InvalidPayloadError(
            `Expected at least ${minimumConfirmations} key-derivation confirmations, received ${confirmations.length}`,
        );
    }

    const seenConfirmations = new Set<number>();
    for (const confirmation of confirmations) {
        if (!qualSet.has(confirmation.payload.participantIndex)) {
            throw new InvalidPayloadError(
                `Key-derivation confirmation came from non-qualified participant ${confirmation.payload.participantIndex}`,
            );
        }
        if (seenConfirmations.has(confirmation.payload.participantIndex)) {
            throw new InvalidPayloadError(
                `Duplicate key-derivation confirmation for participant ${confirmation.payload.participantIndex}`,
            );
        }
        seenConfirmations.add(confirmation.payload.participantIndex);

        if (confirmation.payload.qualHash !== qualHash) {
            throw new InvalidPayloadError(
                `qualHash mismatch in confirmation from participant ${confirmation.payload.participantIndex}`,
            );
        }
        if (confirmation.payload.publicKey !== derivedPublicKey) {
            throw new InvalidPayloadError(
                `Joint public key mismatch in confirmation from participant ${confirmation.payload.participantIndex}`,
            );
        }
    }

    return qualHash;
};
