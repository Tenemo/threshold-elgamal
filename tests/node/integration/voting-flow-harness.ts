import {
    computeRosterHash,
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
    verifyAndAggregateBallots,
    verifyPublishedVotingResult,
    type KeyDerivationConfirmation,
} from '#protocol';
import { bigintToFixedHex } from '#serialize';
import {
    combineDecryptionShares,
    createVerifiedDecryptionShare,
    type Share,
} from '#threshold';

export type {
    AbortedVotingFlowResult,
    ComplaintInjection,
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
        scenario.participantCount >= 2,
        'Integration scenarios require at least two participants',
    );
    invariant(
        scenario.votes.length === scenario.participantCount,
        'Scenario votes must match the participant count',
    );

    const threshold = majorityThreshold(scenario.participantCount);
    if (scenario.threshold !== undefined) {
        invariant(
            scenario.threshold === threshold,
            `Supported DKG threshold must equal ceil(n / 2) = ${threshold}`,
        );
    }

    const validValues = validScores(scenario);
    const bound = singleBallotBound(scenario);

    scenario.votes.forEach((vote, index) => {
        invariant(
            validValues.includes(vote),
            `Vote ${vote.toString()} for participant ${index + 1} is outside the allowed domain`,
        );
        invariant(
            vote <= bound,
            'Vote exceeds the supported single-ballot bound',
        );
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
        `nonce-${scenario.participantCount}-${threshold}-${scenario.votes.join('-')}`,
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

    const qual = participants
        .map((participant) => participant.index)
        .filter((index) => !complainedDealerIndices.has(index));
    const qualDealerMaterials = dealerMaterials.filter((dealer) =>
        qual.includes(dealer.participantIndex),
    );
    const feldmanPayloads = qualDealerMaterials.map(
        (dealer) => dealer.feldmanCommitmentPayload,
    );

    const preConfirmationTranscript = [
        manifestPublication,
        ...registrations,
        ...acceptances,
        ...dealerMaterials.map((dealer) => dealer.pedersenCommitmentPayload),
        ...allEncryptedSharePayloads,
        ...complaintPayloads,
        ...complaintResolutionPayloads,
        ...feldmanPayloads,
    ] as const;
    const preConfirmationQualHash = await hashProtocolTranscript(
        preConfirmationTranscript.map((item) => item.payload),
    );
    const confirmations = await Promise.all(
        qual.map((participantIndex) =>
            signPayload(participants[participantIndex - 1].auth.privateKey, {
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
                                accumulator * dealer.feldmanCommitments[0],
                                group.p,
                            ),
                        1n,
                    ),
                    group.byteLength,
                ),
            } satisfies KeyDerivationConfirmation),
        ),
    );

    const dkgTranscript = [
        manifestPublication,
        ...registrations,
        ...acceptances,
        ...dealerMaterials.map((dealer) => dealer.pedersenCommitmentPayload),
        ...allEncryptedSharePayloads,
        ...complaintPayloads,
        ...complaintResolutionPayloads,
        ...feldmanPayloads,
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
        JSON.stringify(finalState.qual) === JSON.stringify(qual),
        'Reducer QUAL set does not match the complaint outcomes',
    );
    invariant(
        JSON.stringify(verifiedTranscript.qual) === JSON.stringify(qual),
        'Verified transcript QUAL set does not match the complaint outcomes',
    );

    const finalShares: readonly Share[] = qual.map((participantIndex) => ({
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

    const ballots = await createBallotArtifacts(
        scenario.votes,
        jointPublicKey,
        group,
        manifestHash,
        sessionId,
        validValues,
        bound,
    );
    const ballotPayloads = await createBallotSubmissionPayloads(
        participants,
        ballots,
        sessionId,
        manifestHash,
        group,
    );
    const verifiedBallots = await verifyAndAggregateBallots({
        ballots: ballots.map((ballot) => ({
            voterIndex: ballot.voterIndex,
            optionIndex: ballot.proofContext.optionIndex ?? 1,
            ciphertext: ballot.ciphertext,
            proof: ballot.proof,
        })),
        publicKey: jointPublicKey,
        validValues,
        group,
        manifestHash,
        sessionId,
        minimumBallotCount: manifest.minimumPublicationThreshold,
    });
    const reversedVerifiedBallots = await verifyAndAggregateBallots({
        ballots: [...ballots].reverse().map((ballot) => ({
            voterIndex: ballot.voterIndex,
            optionIndex: ballot.proofContext.optionIndex ?? 1,
            ciphertext: ballot.ciphertext,
            proof: ballot.proof,
        })),
        publicKey: jointPublicKey,
        validValues,
        group,
        manifestHash,
        sessionId,
        minimumBallotCount: manifest.minimumPublicationThreshold,
    });
    const aggregate = verifiedBallots.aggregate.ciphertext;
    const reverseAggregate = reversedVerifiedBallots.aggregate.ciphertext;

    invariant(
        reverseAggregate.c1 === aggregate.c1 &&
            reverseAggregate.c2 === aggregate.c2,
        'Aggregate recomputation must be order-independent',
    );

    const mismatchedAggregate = ballots
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
        'Dropped-ballot aggregate should not equal the full aggregate',
    );

    const ballotLogHash = verifiedBallots.transcriptHash;
    const verifiedAggregate = verifiedBallots.aggregate;

    const selectedIndices =
        scenario.decryptionParticipantIndices ?? qual.slice(0, threshold);

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

    const thresholdShareArtifacts = await createThresholdShareArtifacts(
        selectedShares,
        verifiedAggregate,
        transcriptDerivedVerificationKeys,
        group,
        manifestHash,
        sessionId,
    );

    const recovered = combineDecryptionShares(
        aggregate,
        thresholdShareArtifacts.map((item) => item.share),
        group,
        BigInt(scenario.participantCount) * bound,
    );
    const recoveredWithAllShares = combineDecryptionShares(
        aggregate,
        finalShares.map((share) =>
            createVerifiedDecryptionShare(verifiedAggregate, share, group),
        ),
        group,
        BigInt(scenario.participantCount) * bound,
    );
    const expectedTally = scenario.votes.reduce((sum, vote) => sum + vote, 0n);
    const decryptionSharePayloads = await createDecryptionSharePayloads(
        participants,
        thresholdShareArtifacts,
        sessionId,
        manifestHash,
        ballotLogHash,
        verifiedAggregate.ballotCount,
        group,
    );
    const tallyPublication = await createTallyPublicationPayload(
        participants[0],
        sessionId,
        manifestHash,
        ballotLogHash,
        verifiedAggregate.ballotCount,
        recovered,
        thresholdShareArtifacts.map((artifact) => artifact.share.index),
        group,
    );
    const verifiedPublished = await verifyPublishedVotingResult({
        protocol: 'gjkr',
        manifest,
        sessionId,
        dkgTranscript,
        ballotPayloads,
        decryptionSharePayloads,
        tallyPublication,
    });

    invariant(
        recovered === expectedTally,
        'Threshold subset recovered the wrong tally',
    );
    invariant(
        recoveredWithAllShares === expectedTally,
        'All-share threshold recovery returned the wrong tally',
    );
    invariant(
        verifiedPublished.tally === expectedTally,
        'Published tally verification returned the wrong tally',
    );
    invariant(
        verifiedPublished.ballots.transcriptHash === ballotLogHash,
        'Published ballot verification returned the wrong transcript hash',
    );
    invariant(
        verifiedPublished.decryptionShares.length ===
            thresholdShareArtifacts.length,
        'Published tally verification accepted the wrong number of decryption shares',
    );

    return {
        aggregate,
        ballotLogHash,
        ballotPayloads,
        ballots,
        complaintResolutions,
        decryptionSharePayloads,
        dkgTranscript,
        directJointSecret,
        expectedTally,
        finalShares,
        finalState: completedState,
        group,
        jointPublicKey,
        manifest,
        manifestHash,
        mismatchedAggregate,
        participantAuthKeys: participants.map((participant) => ({
            index: participant.index,
            privateKey: participant.auth.privateKey,
        })),
        recovered,
        recoveredWithAllShares,
        registrations,
        sessionFingerprint,
        sessionId,
        tallyPublication,
        thresholdShareArtifacts,
        transcriptDerivedVerificationKeys,
    } satisfies CompletedVotingFlowResult;
};
