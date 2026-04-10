import { createDeterministicSource } from '../deterministic.js';

import { invariant, signPayload } from './common.js';
import type {
    BallotArtifact,
    ParticipantRuntime,
    ThresholdShareArtifact,
} from './types.js';

import { type CryptoGroup, EncodedPoint } from '#core';
import { encryptAdditiveWithRandomness } from '#elgamal';
import {
    createDLEQProof,
    createDisjunctiveProof,
    verifyDLEQProof,
    verifyDisjunctiveProof,
    type DLEQStatement,
    type ProofContext,
} from '#proofs';
import {
    encodeCiphertext,
    encodeCompactProof,
    encodeDisjunctiveProof,
    type BallotSubmissionPayload,
    type DecryptionSharePayload,
    type SignedPayload,
    type TallyPublicationPayload,
    type VerifiedBallotAggregation,
} from '#protocol';
import { encodeScalar } from '#src/core/ristretto';
import { createVerifiedDecryptionShare, type Share } from '#threshold';

export const createBallotArtifacts = async (
    votes: readonly bigint[],
    jointPublicKey: EncodedPoint,
    group: CryptoGroup,
    protocolVersion: string,
    manifestHash: string,
    sessionId: string,
    validValues: readonly bigint[],
    bound: bigint,
    optionIndex = 1,
): Promise<readonly BallotArtifact[]> =>
    Promise.all(
        votes.map(async (vote, offset) => {
            const voterIndex = offset + 1;
            const randomness = BigInt(101 + offset * 103);
            const ciphertext = encryptAdditiveWithRandomness(
                vote,
                jointPublicKey,
                randomness,
                bound,
                group.name,
            );
            const proofContext: ProofContext = {
                protocolVersion,
                suiteId: group.name,
                manifestHash,
                sessionId,
                label: 'ballot-range-proof',
                voterIndex,
                optionIndex,
            };
            const proof = await createDisjunctiveProof(
                vote,
                randomness,
                ciphertext,
                jointPublicKey,
                validValues,
                group,
                proofContext,
                createDeterministicSource(voterIndex * 31, {
                    postCallOffset: 17,
                }),
            );

            invariant(
                await verifyDisjunctiveProof(
                    proof,
                    ciphertext,
                    jointPublicKey,
                    validValues,
                    group,
                    proofContext,
                ),
                `Ballot proof verification failed for voter ${voterIndex}`,
            );

            return {
                voterIndex,
                vote,
                ciphertext,
                proof,
                proofContext,
            };
        }),
    );

export const createBallotSubmissionPayloads = async (
    participants: readonly ParticipantRuntime[],
    ballots: readonly BallotArtifact[],
    sessionId: string,
    manifestHash: string,
    group: CryptoGroup,
): Promise<readonly SignedPayload<BallotSubmissionPayload>[]> =>
    Promise.all(
        ballots.map((ballot) =>
            signPayload(participants[ballot.voterIndex - 1].auth.privateKey, {
                sessionId,
                manifestHash,
                phase: 5,
                participantIndex: ballot.voterIndex,
                messageType: 'ballot-submission',
                optionIndex: ballot.proofContext.optionIndex ?? 1,
                ciphertext: encodeCiphertext(
                    ballot.ciphertext,
                    group.byteLength,
                ),
                proof: encodeDisjunctiveProof(ballot.proof, group.byteLength),
            }),
        ),
    );

export const createThresholdShareArtifacts = async (
    selectedShares: readonly Share[],
    aggregate: VerifiedBallotAggregation['aggregate'],
    transcriptDerivedVerificationKeys: readonly {
        readonly index: number;
        readonly value: EncodedPoint;
    }[],
    group: CryptoGroup,
    protocolVersion: string,
    manifestHash: string,
    sessionId: string,
    optionIndex = 1,
): Promise<readonly ThresholdShareArtifact[]> =>
    Promise.all(
        selectedShares.map(async (share) => {
            const decryptionShare = createVerifiedDecryptionShare(
                aggregate,
                share,
                group,
            );
            const transcriptKey = transcriptDerivedVerificationKeys.find(
                (item) => item.index === share.index,
            );

            invariant(
                transcriptKey !== undefined,
                `Missing transcript-derived key for participant ${share.index}`,
            );

            const statement: DLEQStatement = {
                publicKey: transcriptKey.value,
                ciphertext: aggregate.ciphertext,
                decryptionShare: decryptionShare.value,
            };
            const proofContext: ProofContext = {
                protocolVersion,
                suiteId: group.name,
                manifestHash,
                sessionId,
                label: 'decryption-share-dleq',
                participantIndex: share.index,
                optionIndex,
            };
            const proof = await createDLEQProof(
                share.value,
                statement,
                group,
                proofContext,
                createDeterministicSource(200 + share.index, {
                    postCallOffset: 17,
                }),
            );

            invariant(
                await verifyDLEQProof(proof, statement, group, proofContext),
                `DLEQ proof verification failed for participant ${share.index}`,
            );

            return {
                proof,
                share: decryptionShare,
            };
        }),
    );

export const createDecryptionSharePayloads = async (
    participants: readonly ParticipantRuntime[],
    shares: readonly ThresholdShareArtifact[],
    sessionId: string,
    manifestHash: string,
    transcriptHash: string,
    ballotCount: number,
    group: CryptoGroup,
    optionIndex = 1,
): Promise<readonly SignedPayload<DecryptionSharePayload>[]> =>
    Promise.all(
        shares.map((artifact) =>
            signPayload(
                participants[artifact.share.index - 1].auth.privateKey,
                {
                    sessionId,
                    manifestHash,
                    phase: 6,
                    participantIndex: artifact.share.index,
                    messageType: 'decryption-share',
                    optionIndex,
                    transcriptHash,
                    ballotCount,
                    decryptionShare: artifact.share.value,
                    proof: encodeCompactProof(artifact.proof, group.byteLength),
                },
            ),
        ),
    );

export const createTallyPublicationPayload = async (
    publisher: ParticipantRuntime,
    sessionId: string,
    manifestHash: string,
    transcriptHash: string,
    ballotCount: number,
    tally: bigint,
    decryptionParticipantIndices: readonly number[],
    _group: CryptoGroup,
    optionIndex = 1,
): Promise<SignedPayload<TallyPublicationPayload>> =>
    signPayload(publisher.auth.privateKey, {
        sessionId,
        manifestHash,
        phase: 7,
        participantIndex: publisher.index,
        messageType: 'tally-publication',
        optionIndex,
        transcriptHash,
        ballotCount,
        tally: encodeScalar(tally),
        decryptionParticipantIndices: [...decryptionParticipantIndices].sort(
            (left, right) => left - right,
        ),
    });
