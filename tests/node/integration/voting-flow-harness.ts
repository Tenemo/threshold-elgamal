import {
    computeRosterHash,
    createPhaseCheckpointPayload,
    createManifestPublicationPayload,
    invariant,
    signPayload,
    verifySignedTranscript,
} from './harness/common.js';
import {
    buildComplaintArtifacts,
    buildDealerMaterial,
} from './harness/dealers.js';
import {
    buildManifest,
    createAcceptancePayloads,
    createParticipants,
    createRegistrationPayloads,
} from './harness/setup.js';
import type {
    CompletedVotingFlowResult,
    VotingFlowScenario,
    VotingFlowResult,
} from './harness/types.js';
import {
    createBallotArtifacts,
    createBallotSubmissionPayloads,
    createDecryptionSharePayloads,
    createTallyPublicationPayload,
    createThresholdShareArtifacts,
} from './harness/voting.js';

import { getGroup, majorityThreshold, modP, modPowP, modQ } from '#core';
import {
    deriveJointPublicKey,
    deriveTranscriptVerificationKeys,
    replayGjkrTranscript,
    verifyDKGTranscript,
    type DKGState,
} from '#dkg';
import { addEncryptedValues } from '#elgamal';
import {
    deriveSessionId,
    formatSessionFingerprint,
    hashElectionManifest,
    hashProtocolTranscript,
    verifyBallotSubmissionPayloadsByOption,
    verifyPublishedVotingResults,
    type KeyDerivationConfirmation,
} from '#protocol';
import { bigintToFixedHex } from '#serialize';
import {
    combineDecryptionShares,
    createVerifiedDecryptionShare,
    type Share,
} from '#threshold';

export type {
    CompletedVotingFlowResult,
    VotingFlowScenario,
    VotingFlowResult,
} from './harness/types.js';

const DEFAULT_GROUP = 'ffdhe2048';

const singleBallotBound = (scenario: VotingFlowScenario): bigint =>
    BigInt(scenario.scoreDomainMax ?? 10);

const validScores = (scenario: VotingFlowScenario): readonly bigint[] =>
    Array.from(
        {
            length:
                (scenario.scoreDomainMax ?? 10) -
                (scenario.allowAbstention ? 0 : 1) +
                1,
        },
        (_value, index) => BigInt(index + (scenario.allowAbstention ? 0 : 1)),
    );

const normalizedVotesByOption = (
    scenario: VotingFlowScenario,
): readonly (readonly bigint[])[] => scenario.votesByOption ?? [scenario.votes];

const votesFingerprint = (
    votesByOption: readonly (readonly bigint[])[],
): string => votesByOption.map((votes) => votes.join('-')).join('|');

const excludeParticipants = <
    TPayload extends {
        readonly payload: { readonly participantIndex: number };
    },
>(
    payloads: readonly TPayload[],
    excluded: ReadonlySet<number>,
): readonly TPayload[] =>
    payloads.filter(
        (payload) => !excluded.has(payload.payload.participantIndex),
    );

const checkpointSigners = (
    qual: readonly number[],
    threshold: number,
    excluded: ReadonlySet<number>,
): readonly number[] => {
    const signers = qual.filter(
        (participantIndex) => !excluded.has(participantIndex),
    );

    invariant(
        signers.length >= threshold,
        `Checkpoint signer subset must contain at least ${threshold} participants`,
    );

    return signers.slice(0, threshold);
};

/**
 * Runs a parameterized end-to-end voting-flow scenario.
 *
 * Aborting scenarios return immediately after the DKG replay reaches the
 * terminal aborted state.
 */
export const runVotingFlowScenario = async (
    scenario: VotingFlowScenario,
): Promise<VotingFlowResult> => {
    invariant(
        scenario.participantCount >= 3,
        'Integration scenarios require at least three participants',
    );
    const votesByOption = normalizedVotesByOption(scenario);
    invariant(
        votesByOption.length >= 1,
        'Scenario must define at least one option vote set',
    );

    invariant(
        scenario.optionList === undefined ||
            scenario.optionList.length === votesByOption.length,
        'Scenario option list must match the number of option vote sets',
    );

    const threshold =
        scenario.threshold ?? majorityThreshold(scenario.participantCount);
    invariant(
        threshold >= majorityThreshold(scenario.participantCount) &&
            threshold <= scenario.participantCount - 1,
        `Supported DKG threshold must satisfy floor(n / 2) + 1 <= k <= n - 1 (received ${threshold} for n = ${scenario.participantCount})`,
    );

    const validValues = validScores(scenario);
    const bound = singleBallotBound(scenario);

    votesByOption.forEach((votes, optionOffset) => {
        invariant(
            votes.length === scenario.participantCount,
            `Scenario votes for option ${optionOffset + 1} must match the participant count`,
        );

        votes.forEach((vote, index) => {
            invariant(
                validValues.includes(vote),
                `Vote ${vote.toString()} for participant ${index + 1} and option ${optionOffset + 1} is outside the allowed domain`,
            );
            invariant(
                vote <= bound,
                'Vote exceeds the supported single-ballot bound',
            );
        });
    });

    const group = getGroup(scenario.group ?? DEFAULT_GROUP);
    const participants = await createParticipants(
        scenario.participantCount,
        scenario.transportSuite ?? 'P-256',
    );
    const rosterHash = await computeRosterHash(participants);
    const manifest = buildManifest(rosterHash, group, scenario);
    const manifestHash = await hashElectionManifest(manifest);
    const sessionId = await deriveSessionId(
        manifestHash,
        rosterHash,
        `nonce-${scenario.participantCount}-${threshold}-${votesFingerprint(votesByOption)}`,
        `2026-04-08T12:${String(scenario.participantCount).padStart(2, '0')}:00Z`,
    );
    const manifestPublication = await createManifestPublicationPayload(
        participants[0],
        sessionId,
        manifestHash,
        manifest,
    );
    const registrations = await createRegistrationPayloads(
        participants,
        sessionId,
        manifestHash,
        rosterHash,
    );
    const acceptances = await createAcceptancePayloads(
        participants,
        sessionId,
        manifestHash,
        rosterHash,
    );

    await verifySignedTranscript(participants, [
        manifestPublication,
        ...registrations,
        ...acceptances,
    ]);

    const setupTranscriptHash = await hashProtocolTranscript(
        [manifestPublication, ...registrations, ...acceptances].map(
            (item) => item.payload,
        ),
    );
    const sessionFingerprint = formatSessionFingerprint(setupTranscriptHash);

    invariant(
        /^[0-9A-F]{4}(?:-[0-9A-F]{4}){7}$/.test(sessionFingerprint),
        'Session fingerprint formatting is invalid',
    );

    const dealerMaterials = await Promise.all(
        participants.map((participant) =>
            buildDealerMaterial(
                participant,
                participants,
                sessionId,
                manifestHash,
                rosterHash,
                group,
                threshold,
            ),
        ),
    );
    const missingPedersenCommitmentIndices = new Set(
        scenario.missingPedersenCommitmentParticipantIndices ?? [],
    );
    const missingEncryptedShareDealerIndices = new Set(
        scenario.missingEncryptedShareDealerIndices ?? [],
    );
    const missingFeldmanCommitmentIndices = new Set(
        scenario.missingFeldmanCommitmentParticipantIndices ?? [],
    );
    const missingKeyDerivationConfirmationIndices = new Set(
        scenario.missingKeyDerivationConfirmationParticipantIndices ?? [],
    );
    const missingCheckpointSignerIndices =
        scenario.missingPhaseCheckpointSignerIndices ?? {};

    const phase0Qual = participants.map((participant) => participant.index);
    const phase0CheckpointSigners = checkpointSigners(
        phase0Qual,
        threshold,
        new Set(missingCheckpointSignerIndices[0] ?? []),
    );
    const phase0CheckpointTranscript = [
        manifestPublication,
        ...registrations,
        ...acceptances,
    ] as const;
    const phase0Checkpoints = await Promise.all(
        phase0CheckpointSigners.map((participantIndex) =>
            createPhaseCheckpointPayload(
                participants[participantIndex - 1],
                sessionId,
                manifestHash,
                phase0CheckpointTranscript,
                0,
                phase0Qual,
            ),
        ),
    );
    const {
        allEncryptedSharePayloads,
        complainedDealerIndices,
        complaintPayloads,
        complaintResolutionPayloads,
        complaintResolutions,
    } = await buildComplaintArtifacts(
        scenario.complaints,
        dealerMaterials,
        participants,
        sessionId,
        manifestHash,
    );
    const pedersenPayloads = excludeParticipants(
        dealerMaterials.map((dealer) => dealer.pedersenCommitmentPayload),
        missingPedersenCommitmentIndices,
    );
    const encryptedSharePayloads = allEncryptedSharePayloads.filter(
        (payload) =>
            !missingEncryptedShareDealerIndices.has(
                payload.payload.participantIndex,
            ),
    );
    const phase1Qual = phase0Qual.filter(
        (participantIndex) =>
            !missingPedersenCommitmentIndices.has(participantIndex) &&
            !missingEncryptedShareDealerIndices.has(participantIndex),
    );
    const phase1CheckpointSigners = checkpointSigners(
        phase1Qual.length >= threshold ? phase1Qual : phase0Qual,
        threshold,
        new Set(missingCheckpointSignerIndices[1] ?? []),
    );
    const phase1CheckpointTranscript = [
        ...phase0CheckpointTranscript,
        ...phase0Checkpoints,
        ...pedersenPayloads,
        ...encryptedSharePayloads,
    ] as const;
    const phase1Checkpoints = await Promise.all(
        phase1CheckpointSigners.map((participantIndex) =>
            createPhaseCheckpointPayload(
                participants[participantIndex - 1],
                sessionId,
                manifestHash,
                phase1CheckpointTranscript,
                1,
                phase1Qual,
            ),
        ),
    );

    const complaintQual = phase1Qual.filter(
        (participantIndex) => !complainedDealerIndices.has(participantIndex),
    );
    const phase2Checkpoints =
        complaintQual.length >= threshold
            ? await Promise.all(
                  checkpointSigners(
                      complaintQual,
                      threshold,
                      new Set(missingCheckpointSignerIndices[2] ?? []),
                  ).map((participantIndex) =>
                      createPhaseCheckpointPayload(
                          participants[participantIndex - 1],
                          sessionId,
                          manifestHash,
                          [
                              ...phase1CheckpointTranscript,
                              ...phase1Checkpoints,
                              ...complaintPayloads,
                              ...complaintResolutionPayloads,
                          ] as const,
                          2,
                          complaintQual,
                      ),
                  ),
              )
            : [];

    const finalQual = complaintQual.filter(
        (participantIndex) =>
            !missingFeldmanCommitmentIndices.has(participantIndex),
    );
    const qualDealerMaterials = dealerMaterials.filter((dealer) =>
        finalQual.includes(dealer.participantIndex),
    );
    const feldmanPayloads = excludeParticipants(
        qualDealerMaterials.map((dealer) => dealer.feldmanCommitmentPayload),
        new Set<number>(),
    );
    const phase3Checkpoints =
        finalQual.length >= threshold
            ? await Promise.all(
                  checkpointSigners(
                      finalQual,
                      threshold,
                      new Set(missingCheckpointSignerIndices[3] ?? []),
                  ).map((participantIndex) =>
                      createPhaseCheckpointPayload(
                          participants[participantIndex - 1],
                          sessionId,
                          manifestHash,
                          [
                              ...phase1CheckpointTranscript,
                              ...phase1Checkpoints,
                              ...complaintPayloads,
                              ...complaintResolutionPayloads,
                              ...phase2Checkpoints,
                              ...feldmanPayloads,
                          ] as const,
                          3,
                          finalQual,
                      ),
                  ),
              )
            : [];

    const preConfirmationTranscript = [
        ...phase0CheckpointTranscript,
        ...phase0Checkpoints,
        ...pedersenPayloads,
        ...encryptedSharePayloads,
        ...phase1Checkpoints,
        ...complaintPayloads,
        ...complaintResolutionPayloads,
        ...phase2Checkpoints,
        ...feldmanPayloads,
        ...phase3Checkpoints,
    ] as const;
    const preConfirmationQualHash = await hashProtocolTranscript(
        preConfirmationTranscript.map((item) => item.payload),
    );
    const confirmations =
        scenario.includeKeyDerivationConfirmations === true &&
        finalQual.length >= threshold
            ? await Promise.all(
                  finalQual
                      .filter(
                          (participantIndex) =>
                              !missingKeyDerivationConfirmationIndices.has(
                                  participantIndex,
                              ),
                      )
                      .map((participantIndex) =>
                          signPayload(
                              participants[participantIndex - 1].auth
                                  .privateKey,
                              {
                                  sessionId,
                                  manifestHash,
                                  phase: 4,
                                  participantIndex,
                                  messageType: 'key-derivation-confirmation',
                                  qualHash: preConfirmationQualHash,
                                  publicKey: bigintToFixedHex(
                                      qualDealerMaterials.reduce(
                                          (accumulator, dealer) =>
                                              modP(
                                                  accumulator *
                                                      dealer
                                                          .feldmanCommitments[0],
                                                  group.p,
                                              ),
                                          1n,
                                      ),
                                      group.byteLength,
                                  ),
                              } satisfies KeyDerivationConfirmation,
                          ),
                      ),
              )
            : [];

    const dkgTranscript = [
        ...phase0CheckpointTranscript,
        ...phase0Checkpoints,
        ...pedersenPayloads,
        ...encryptedSharePayloads,
        ...phase1Checkpoints,
        ...complaintPayloads,
        ...complaintResolutionPayloads,
        ...phase2Checkpoints,
        ...feldmanPayloads,
        ...phase3Checkpoints,
        ...confirmations,
    ] as const;
    await verifySignedTranscript(participants, dkgTranscript);
    const finalState = replayGjkrTranscript(
        {
            protocol: 'gjkr',
            sessionId,
            manifestHash,
            group: group.name,
            participantCount: scenario.participantCount,
            threshold,
        },
        dkgTranscript,
    );

    if (finalState.phase === 'aborted') {
        const abortedState = finalState as DKGState & {
            readonly phase: 'aborted';
        };

        return {
            aggregate: { c1: 1n, c2: 1n },
            ballots: [],
            complaintResolutions,
            dkgTranscript,
            dkgPhaseCheckpoints: [
                ...phase0Checkpoints,
                ...phase1Checkpoints,
                ...phase2Checkpoints,
                ...phase3Checkpoints,
            ],
            manifest,
            finalState: abortedState,
            group,
            manifestHash,
            participantAuthKeys: participants.map((participant) => ({
                index: participant.index,
                privateKey: participant.auth.privateKey,
            })),
            registrations,
            sessionFingerprint,
            sessionId,
        };
    }

    const verifiedTranscript = await verifyDKGTranscript({
        protocol: 'gjkr',
        transcript: dkgTranscript,
        manifest,
        sessionId,
    });

    invariant(
        finalState.phase === 'completed',
        'Expected the DKG scenario to complete',
    );
    const completedState = finalState as DKGState & {
        readonly phase: 'completed';
    };
    invariant(
        JSON.stringify(finalState.qual) === JSON.stringify(finalQual),
        'Reducer QUAL set does not match the checkpointed DKG outcomes',
    );
    invariant(
        JSON.stringify(verifiedTranscript.qual) === JSON.stringify(finalQual),
        'Verified transcript QUAL set does not match the checkpointed DKG outcomes',
    );

    const finalShares: readonly Share[] = finalQual.map((participantIndex) => ({
        index: participantIndex,
        value: modQ(
            qualDealerMaterials.reduce(
                (sum, dealer) =>
                    sum +
                    dealer.pedersenShares[participantIndex - 1].secretValue,
                0n,
            ),
            group.q,
        ),
    }));
    const jointPublicKey = deriveJointPublicKey(
        qualDealerMaterials.map((dealer) => ({
            dealerIndex: dealer.participantIndex,
            commitments: dealer.feldmanCommitments,
        })),
        group,
    );
    const directJointSecret = modQ(
        qualDealerMaterials.reduce(
            (sum, dealer) => sum + dealer.secretPolynomial[0],
            0n,
        ),
        group.q,
    );

    invariant(
        jointPublicKey === modPowP(group.g, directJointSecret, group.p),
        'Joint public key does not match the direct secret sum',
    );
    invariant(
        verifiedTranscript.derivedPublicKey === jointPublicKey,
        'Verified transcript public key does not match the derived joint public key',
    );

    const transcriptDerivedVerificationKeys = deriveTranscriptVerificationKeys(
        verifiedTranscript.feldmanCommitments,
        finalShares.map((share) => share.index),
        group,
    );
    transcriptDerivedVerificationKeys.forEach((transcriptKey, offset) => {
        invariant(
            transcriptKey.value ===
                modPowP(group.g, finalShares[offset].value, group.p),
            `Transcript-derived verification key mismatch for participant ${transcriptKey.index}`,
        );
    });

    const ballotsByOption = await Promise.all(
        votesByOption.map((votes, optionOffset) =>
            createBallotArtifacts(
                votes,
                jointPublicKey,
                group,
                manifestHash,
                sessionId,
                validValues,
                bound,
                optionOffset + 1,
            ),
        ),
    );
    const ballots = ballotsByOption.flat();
    const ballotPayloads = await createBallotSubmissionPayloads(
        participants,
        ballots,
        sessionId,
        manifestHash,
        group,
    );
    const verifiedBallotsByOption =
        await verifyBallotSubmissionPayloadsByOption({
            ballotPayloads,
            publicKey: jointPublicKey,
            manifest,
            sessionId,
        });
    const reversedVerifiedBallotsByOption =
        await verifyBallotSubmissionPayloadsByOption({
            ballotPayloads: [...ballotPayloads].reverse(),
            publicKey: jointPublicKey,
            manifest,
            sessionId,
        });

    verifiedBallotsByOption.forEach((verifiedBallots, offset) => {
        const reversedBallots = reversedVerifiedBallotsByOption[offset];
        invariant(
            reversedBallots !== undefined,
            `Missing reversed ballot verification for option ${verifiedBallots.optionIndex}`,
        );
        invariant(
            reversedBallots.aggregate.ciphertext.c1 ===
                verifiedBallots.aggregate.ciphertext.c1 &&
                reversedBallots.aggregate.ciphertext.c2 ===
                    verifiedBallots.aggregate.ciphertext.c2,
            `Aggregate recomputation must be order-independent for option ${verifiedBallots.optionIndex}`,
        );
        invariant(
            reversedBallots.transcriptHash === verifiedBallots.transcriptHash,
            `Transcript hashing must be order-independent for option ${verifiedBallots.optionIndex}`,
        );
    });

    const selectedIndices =
        scenario.decryptionParticipantIndices ?? finalQual.slice(0, threshold);

    invariant(
        selectedIndices.length >= threshold,
        'Scenario decryption subset must contain at least threshold participants',
    );

    const selectedShares = selectedIndices.map((index) => {
        const share = finalShares.find((item) => item.index === index);
        invariant(
            share !== undefined,
            `Missing final share for selected participant ${index}`,
        );
        return share;
    });

    const optionResults = await Promise.all(
        verifiedBallotsByOption.map(async (verifiedBallots, offset) => {
            const optionBallots = ballotsByOption[offset] ?? [];
            const optionIndex = verifiedBallots.optionIndex;
            const aggregate = verifiedBallots.aggregate.ciphertext;
            const mismatchedAggregate = optionBallots
                .slice(0, -1)
                .map((ballot) => ballot.ciphertext)
                .reduce(
                    (accumulator, ciphertext) =>
                        addEncryptedValues(accumulator, ciphertext, group.name),
                    { c1: 1n, c2: 1n },
                );

            invariant(
                mismatchedAggregate.c1 !== aggregate.c1 ||
                    mismatchedAggregate.c2 !== aggregate.c2,
                `Dropped-ballot aggregate should not equal the full aggregate for option ${optionIndex}`,
            );

            const thresholdShareArtifacts = await createThresholdShareArtifacts(
                selectedShares,
                verifiedBallots.aggregate,
                transcriptDerivedVerificationKeys,
                group,
                manifestHash,
                sessionId,
                optionIndex,
            );
            const recovered = combineDecryptionShares(
                aggregate,
                thresholdShareArtifacts.map((item) => item.share),
                group,
                BigInt(verifiedBallots.aggregate.ballotCount) * bound,
            );
            const recoveredWithAllShares = combineDecryptionShares(
                aggregate,
                finalShares.map((share) =>
                    createVerifiedDecryptionShare(
                        verifiedBallots.aggregate,
                        share,
                        group,
                    ),
                ),
                group,
                BigInt(verifiedBallots.aggregate.ballotCount) * bound,
            );
            const expectedTally = votesByOption[offset].reduce(
                (sum, vote) => sum + vote,
                0n,
            );
            const decryptionSharePayloads = await createDecryptionSharePayloads(
                participants,
                thresholdShareArtifacts,
                sessionId,
                manifestHash,
                verifiedBallots.transcriptHash,
                verifiedBallots.aggregate.ballotCount,
                group,
                optionIndex,
            );
            const tallyPublication = await createTallyPublicationPayload(
                participants[0],
                sessionId,
                manifestHash,
                verifiedBallots.transcriptHash,
                verifiedBallots.aggregate.ballotCount,
                recovered,
                thresholdShareArtifacts.map((artifact) => artifact.share.index),
                group,
                optionIndex,
            );

            invariant(
                recovered === expectedTally,
                `Threshold subset recovered the wrong tally for option ${optionIndex}`,
            );
            invariant(
                recoveredWithAllShares === expectedTally,
                `All-share threshold recovery returned the wrong tally for option ${optionIndex}`,
            );

            return {
                optionIndex,
                aggregate,
                ballotLogHash: verifiedBallots.transcriptHash,
                ballots: optionBallots,
                expectedTally,
                mismatchedAggregate,
                recovered,
                recoveredWithAllShares,
                tallyPublication,
                thresholdShareArtifacts,
                decryptionSharePayloads,
            };
        }),
    );

    const decryptionSharePayloads = optionResults.flatMap(
        (result) => result.decryptionSharePayloads,
    );
    const tallyPublications = optionResults.map(
        (result) => result.tallyPublication,
    );
    const verifiedPublished = await verifyPublishedVotingResults({
        protocol: 'gjkr',
        manifest,
        sessionId,
        dkgTranscript,
        ballotPayloads,
        decryptionSharePayloads,
        tallyPublications,
    });

    optionResults.forEach((result) => {
        const verifiedOption = verifiedPublished.options.find(
            (entry) => entry.optionIndex === result.optionIndex,
        );

        invariant(
            verifiedOption !== undefined,
            `Missing verified published tally for option ${result.optionIndex}`,
        );
        invariant(
            verifiedOption.tally === result.expectedTally,
            `Published tally verification returned the wrong tally for option ${result.optionIndex}`,
        );
        invariant(
            verifiedOption.ballots.transcriptHash === result.ballotLogHash,
            `Published ballot verification returned the wrong transcript hash for option ${result.optionIndex}`,
        );
        invariant(
            verifiedOption.decryptionShares.length ===
                result.thresholdShareArtifacts.length,
            `Published tally verification accepted the wrong number of decryption shares for option ${result.optionIndex}`,
        );
    });

    const primaryOption = optionResults[0];

    return {
        aggregate: primaryOption.aggregate,
        ballotLogHash: primaryOption.ballotLogHash,
        ballotPayloads,
        ballots,
        complaintResolutions,
        decryptionSharePayloads,
        dkgTranscript,
        dkgPhaseCheckpoints: [
            ...phase0Checkpoints,
            ...phase1Checkpoints,
            ...phase2Checkpoints,
            ...phase3Checkpoints,
        ],
        directJointSecret,
        expectedTally: primaryOption.expectedTally,
        finalShares,
        finalState: completedState,
        group,
        jointPublicKey,
        manifest,
        manifestHash,
        mismatchedAggregate: primaryOption.mismatchedAggregate,
        optionResults: optionResults.map((result) => ({
            aggregate: result.aggregate,
            ballotLogHash: result.ballotLogHash,
            ballots: result.ballots,
            expectedTally: result.expectedTally,
            mismatchedAggregate: result.mismatchedAggregate,
            optionIndex: result.optionIndex,
            recovered: result.recovered,
            recoveredWithAllShares: result.recoveredWithAllShares,
            tallyPublication: result.tallyPublication,
            thresholdShareArtifacts: result.thresholdShareArtifacts,
        })),
        participantAuthKeys: participants.map((participant) => ({
            index: participant.index,
            privateKey: participant.auth.privateKey,
        })),
        recovered: primaryOption.recovered,
        recoveredWithAllShares: primaryOption.recoveredWithAllShares,
        registrations,
        sessionFingerprint,
        sessionId,
        tallyPublication: primaryOption.tallyPublication,
        tallyPublications,
        thresholdShareArtifacts: primaryOption.thresholdShareArtifacts,
        transcriptDerivedVerificationKeys,
    } satisfies CompletedVotingFlowResult;
};
