import { TextEncoder } from 'node:util';

import {
    combineDecryptionShares,
    createBallotClosePayload,
    createBallotSubmissionPayload,
    createDecryptionShare,
    createDecryptionSharePayload,
    createDLEQProof,
    createDisjunctiveProof,
    createElectionManifest,
    createEncryptedDualSharePayload,
    createFeldmanCommitmentPayload,
    createKeyDerivationConfirmationPayload,
    createManifestAcceptancePayload,
    createManifestPublicationPayload,
    createSchnorrProof,
    createPhaseCheckpointPayload,
    createPedersenCommitmentPayload,
    createRegistrationPayload,
    createTallyPublicationPayload,
    deriveJointPublicKey,
    derivePedersenShares,
    deriveSessionId,
    deriveTranscriptVerificationKey,
    encryptEnvelope,
    encryptAdditiveWithRandomness,
    encodePedersenShareEnvelope,
    exportAuthPublicKey,
    exportTransportPublicKey,
    generateFeldmanCommitments,
    generateAuthKeyPair,
    generatePedersenCommitments,
    generateTransportKeyPair,
    hashElectionManifest,
    hashProtocolTranscript,
    hashRosterEntries,
    majorityThreshold,
    modQ,
    prepareAggregateForDecryption,
    RISTRETTO_GROUP,
    scoreRangeDomain,
    SHIPPED_PROTOCOL_VERSION,
    signProtocolPayload,
    verifyBallotSubmissionPayloadsByOption,
    verifyElectionCeremony,
    type BallotClosePayload,
    type BallotSubmissionPayload,
    type DecryptionSharePayload,
    type DLEQStatement,
    type ElectionManifest,
    type EncodedPoint,
    type EncodedAuthPublicKey,
    type EncodedTransportPublicKey,
    type EncryptedDualSharePayload,
    type KeyDerivationConfirmation,
    type ProofContext,
    type ScoreRange,
    type SignedPayload,
    type TallyPublicationPayload,
    type TransportKeyPair,
} from '#root';

export type VotingFlowParticipant = {
    readonly auth: CryptoKeyPair;
    readonly authPublicKey: EncodedAuthPublicKey;
    readonly index: number;
    readonly transport: TransportKeyPair;
    readonly transportPublicKey: EncodedTransportPublicKey;
};

type DKGComplaintScenario = {
    readonly complainantIndex: number;
    readonly dealerIndex: number;
    readonly outcome?: 'accepted' | 'rejected';
    readonly reason?:
        | 'aes-gcm-failure'
        | 'malformed-plaintext'
        | 'pedersen-failure';
};

type DealerEncryptedShareEntry = {
    readonly ephemeralPrivateKey: Awaited<
        ReturnType<typeof encryptEnvelope>
    >['ephemeralPrivateKey'];
    readonly payload: SignedPayload<EncryptedDualSharePayload>;
    readonly recipientIndex: number;
};

type DealerArtifacts = {
    readonly encryptedShareEntries: readonly DealerEncryptedShareEntry[];
    readonly encryptedSharePayloads: readonly SignedPayload[];
    readonly feldmanCommitments: readonly EncodedPoint[];
    readonly feldmanPayload: SignedPayload;
    readonly pedersenPayload: SignedPayload;
    readonly shares: ReturnType<typeof derivePedersenShares>;
};

export type VotingFlowScenario = {
    readonly ballotRandomness?: readonly (readonly bigint[])[];
    readonly closeParticipantIndices?: readonly number[];
    readonly dkgComplaint?: DKGComplaintScenario;
    readonly includePhaseCheckpoints?: boolean;
    readonly optionCount?: number;
    readonly optionList?: readonly string[];
    readonly participantCount: number;
    readonly participantVotes?: readonly (readonly bigint[])[];
    readonly scoreRange: ScoreRange;
    readonly sessionNonce?: string;
    readonly timestamp?: string;
    readonly votingParticipantIndices?: readonly number[];
};

export type CompletedVotingFlowResult = {
    readonly ballotClosePayload: SignedPayload<BallotClosePayload>;
    readonly ballotPayloads: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly countedParticipantIndices: readonly number[];
    readonly decryptionSharePayloads: readonly SignedPayload<DecryptionSharePayload>[];
    readonly dkgTranscript: readonly SignedPayload[];
    readonly expectedTallies: readonly bigint[];
    readonly finalShares: readonly {
        readonly index: number;
        readonly value: bigint;
    }[];
    readonly manifest: ElectionManifest;
    readonly manifestHash: string;
    readonly participants: readonly VotingFlowParticipant[];
    readonly participantVotes: readonly (readonly bigint[])[];
    readonly qualifiedParticipantIndices: readonly number[];
    readonly rosterHash: string;
    readonly sessionId: string;
    readonly tallyPublications: readonly SignedPayload<TallyPublicationPayload>[];
    readonly threshold: number;
    readonly verified: Awaited<ReturnType<typeof verifyElectionCeremony>>;
    readonly votingParticipantIndices: readonly number[];
};

const assert = (condition: boolean, message: string): void => {
    if (!condition) {
        throw new Error(message);
    }
};

const corruptHexTailByte = (value: string): string => {
    const lastByte = Number.parseInt(value.slice(-2), 16);
    const corruptedByte = (lastByte ^ 0x01).toString(16).padStart(2, '0');

    return `${value.slice(0, -2)}${corruptedByte}`;
};

const coefficientValue = (
    dealerIndex: number,
    coefficientIndex: number,
    q: bigint,
    offset: number,
): bigint =>
    modQ(BigInt(dealerIndex * 97 + coefficientIndex * 31 + offset), q - 1n) +
    1n;

const buildPolynomial = (
    dealerIndex: number,
    threshold: number,
    q: bigint,
    offset: number,
): readonly bigint[] =>
    Array.from({ length: threshold }, (_value, coefficientIndex) =>
        coefficientValue(dealerIndex, coefficientIndex, q, offset),
    );

const buildDefaultParticipantVotes = (
    participantCount: number,
    optionCount: number,
    scoreRange: ScoreRange,
): readonly (readonly bigint[])[] =>
    Array.from({ length: participantCount }, (_value, participantOffset) =>
        Array.from({ length: optionCount }, (_entry, optionOffset) =>
            BigInt(
                scoreRange.min +
                    ((participantOffset + optionOffset * 2) %
                        (scoreRange.max - scoreRange.min + 1)),
            ),
        ),
    );

const normalizeScoreRange = (scoreRange: ScoreRange): ScoreRange => {
    if (!Number.isSafeInteger(scoreRange.min)) {
        throw new Error(
            'Voting flow scenario scoreRange.min must be a safe integer',
        );
    }
    if (!Number.isSafeInteger(scoreRange.max)) {
        throw new Error(
            'Voting flow scenario scoreRange.max must be a safe integer',
        );
    }
    if (scoreRange.min < 0) {
        throw new Error(
            'Voting flow scenario scoreRange.min must be non-negative',
        );
    }
    if (scoreRange.max < 0) {
        throw new Error(
            'Voting flow scenario scoreRange.max must be non-negative',
        );
    }
    if (scoreRange.min > scoreRange.max) {
        throw new Error(
            'Voting flow scenario scoreRange.min must not exceed scoreRange.max',
        );
    }

    return scoreRange;
};

const defaultBallotRandomness = (
    participantIndex: number,
    optionIndex: number,
): bigint => BigInt(1000 + participantIndex * 97 + optionIndex * 31);

const normalizeOptionList = (
    scenario: VotingFlowScenario,
): readonly string[] => {
    const inferredOptionCount =
        scenario.optionList?.length ??
        scenario.optionCount ??
        scenario.participantVotes?.[0]?.length ??
        2;

    assert(
        Number.isInteger(inferredOptionCount) && inferredOptionCount >= 1,
        'Voting flow scenarios require at least one option',
    );

    if (
        scenario.optionList !== undefined &&
        scenario.optionCount !== undefined &&
        scenario.optionList.length !== scenario.optionCount
    ) {
        throw new Error(
            'Voting flow scenario optionList length must match optionCount',
        );
    }

    return (
        scenario.optionList ??
        Array.from(
            { length: inferredOptionCount },
            (_value, index) => `Option ${index + 1}`,
        )
    );
};

const normalizeParticipantVotes = (
    scenario: VotingFlowScenario,
    optionCount: number,
    scoreRange: ScoreRange,
): readonly (readonly bigint[])[] => {
    const participantVotes =
        scenario.participantVotes ??
        buildDefaultParticipantVotes(
            scenario.participantCount,
            optionCount,
            scoreRange,
        );
    const minScore = BigInt(scoreRange.min);
    const maxScore = BigInt(scoreRange.max);

    if (participantVotes.length !== scenario.participantCount) {
        throw new Error(
            `Voting flow scenario requires exactly ${scenario.participantCount} participant vote rows`,
        );
    }

    participantVotes.forEach((votes, participantOffset) => {
        if (votes.length !== optionCount) {
            throw new Error(
                `Participant ${participantOffset + 1} vote row must include exactly ${optionCount} option scores`,
            );
        }

        votes.forEach((vote, optionOffset) => {
            if (typeof vote !== 'bigint') {
                throw new Error(
                    `Participant ${participantOffset + 1} option ${optionOffset + 1} vote must be a bigint`,
                );
            }
            if (vote < minScore || vote > maxScore) {
                throw new Error(
                    `Participant ${participantOffset + 1} option ${optionOffset + 1} vote must stay within ${scoreRange.min}..${scoreRange.max}`,
                );
            }
        });
    });

    return participantVotes;
};

const normalizeBallotRandomness = (
    scenario: VotingFlowScenario,
    optionCount: number,
): readonly (readonly bigint[])[] | undefined => {
    const ballotRandomness = scenario.ballotRandomness;

    if (ballotRandomness === undefined) {
        return undefined;
    }

    if (ballotRandomness.length !== scenario.participantCount) {
        throw new Error(
            `Voting flow scenario requires exactly ${scenario.participantCount} ballot-randomness rows`,
        );
    }

    ballotRandomness.forEach((randomnessRow, participantOffset) => {
        if (randomnessRow.length !== optionCount) {
            throw new Error(
                `Participant ${participantOffset + 1} ballot-randomness row must include exactly ${optionCount} option values`,
            );
        }
    });

    return ballotRandomness;
};

const normalizeParticipantIndices = (
    participantIndices: readonly number[],
    participantCount: number,
    label: string,
): readonly number[] => {
    const normalized = [...participantIndices].sort(
        (left, right) => left - right,
    );

    normalized.forEach((participantIndex, offset) => {
        if (
            !Number.isInteger(participantIndex) ||
            participantIndex < 1 ||
            participantIndex > participantCount
        ) {
            throw new Error(
                `${label} participant indices must stay within 1..${participantCount}`,
            );
        }
        if (offset > 0 && participantIndex === normalized[offset - 1]) {
            throw new Error(`${label} participant indices must be unique`);
        }
    });

    return normalized;
};

const buildParticipants = async (
    participantCount: number,
): Promise<readonly VotingFlowParticipant[]> =>
    Promise.all(
        Array.from({ length: participantCount }, async (_value, offset) => {
            const index = offset + 1;
            const auth = await generateAuthKeyPair({ extractable: true });
            const transport = await generateTransportKeyPair({
                extractable: true,
            });

            return {
                auth,
                authPublicKey: await exportAuthPublicKey(auth.publicKey),
                index,
                transport,
                transportPublicKey: await exportTransportPublicKey(
                    transport.publicKey,
                ),
            };
        }),
    );

const buildDealerArtifacts = async (
    participant: VotingFlowParticipant,
    participants: readonly VotingFlowParticipant[],
    sessionId: string,
    manifestHash: string,
    rosterHash: string,
    threshold: number,
    complaintScenario?: DKGComplaintScenario,
): Promise<DealerArtifacts> => {
    const secretPolynomial = buildPolynomial(
        participant.index,
        threshold,
        RISTRETTO_GROUP.q,
        7,
    );
    const blindingPolynomial = buildPolynomial(
        participant.index,
        threshold,
        RISTRETTO_GROUP.q,
        43,
    );
    const pedersenCommitments = generatePedersenCommitments(
        secretPolynomial,
        blindingPolynomial,
        RISTRETTO_GROUP,
    );
    const shares = derivePedersenShares(
        secretPolynomial,
        blindingPolynomial,
        participants.length,
        RISTRETTO_GROUP.q,
    );
    const feldmanCommitments = generateFeldmanCommitments(
        secretPolynomial,
        RISTRETTO_GROUP,
    );
    const pedersenPayload = await createPedersenCommitmentPayload(
        participant.auth.privateKey,
        {
            sessionId,
            manifestHash,
            participantIndex: participant.index,
            commitments: pedersenCommitments.commitments,
        },
    );
    const proofs = await Promise.all(
        secretPolynomial.map(async (coefficient, offset) => {
            const coefficientIndex = offset + 1;
            const context: ProofContext = {
                protocolVersion: SHIPPED_PROTOCOL_VERSION,
                suiteId: RISTRETTO_GROUP.name,
                manifestHash,
                sessionId,
                label: 'feldman-coefficient-proof',
                participantIndex: participant.index,
                coefficientIndex,
            };
            const proof = await createSchnorrProof(
                coefficient,
                feldmanCommitments.commitments[offset],
                RISTRETTO_GROUP,
                context,
            );

            return {
                coefficientIndex,
                challenge: proof.challenge,
                response: proof.response,
            };
        }),
    );
    const feldmanPayload = await createFeldmanCommitmentPayload(
        participant.auth.privateKey,
        {
            sessionId,
            manifestHash,
            participantIndex: participant.index,
            commitments: feldmanCommitments.commitments,
            proofs,
        },
    );
    const encryptedShareEntries = await Promise.all(
        participants
            .filter((recipient) => recipient.index !== participant.index)
            .map(async (recipient) => {
                const share = shares[recipient.index - 1];
                const plaintext = new TextEncoder().encode(
                    encodePedersenShareEnvelope(
                        share,
                        RISTRETTO_GROUP.byteLength,
                    ),
                );
                const { envelope, ephemeralPrivateKey } = await encryptEnvelope(
                    plaintext,
                    recipient.transportPublicKey,
                    {
                        sessionId,
                        rosterHash,
                        phase: 1,
                        dealerIndex: participant.index,
                        recipientIndex: recipient.index,
                        envelopeId: `env-${participant.index}-${recipient.index}`,
                        payloadType: 'encrypted-dual-share',
                        protocolVersion: SHIPPED_PROTOCOL_VERSION,
                        suite: recipient.transport.suite,
                    },
                );
                const publishedEnvelope =
                    complaintScenario?.outcome === 'accepted' &&
                    complaintScenario.dealerIndex === participant.index &&
                    complaintScenario.complainantIndex === recipient.index
                        ? {
                              ...envelope,
                              ciphertext: corruptHexTailByte(
                                  envelope.ciphertext,
                              ),
                          }
                        : envelope;

                return {
                    ephemeralPrivateKey,
                    payload: await createEncryptedDualSharePayload(
                        participant.auth.privateKey,
                        {
                            sessionId,
                            manifestHash,
                            participantIndex: participant.index,
                            recipientIndex: recipient.index,
                            envelopeId: publishedEnvelope.envelopeId,
                            suite: publishedEnvelope.suite,
                            ephemeralPublicKey:
                                publishedEnvelope.ephemeralPublicKey,
                            iv: publishedEnvelope.iv,
                            ciphertext: publishedEnvelope.ciphertext,
                        },
                    ),
                    recipientIndex: recipient.index,
                } satisfies DealerEncryptedShareEntry;
            }),
    );

    return {
        encryptedShareEntries,
        encryptedSharePayloads: encryptedShareEntries.map(
            (entry) => entry.payload,
        ),
        feldmanCommitments: feldmanCommitments.commitments,
        feldmanPayload,
        pedersenPayload,
        shares,
    };
};

const createComplaintPayloads = async (input: {
    readonly complaintScenario: DKGComplaintScenario;
    readonly dealerArtifacts: readonly DealerArtifacts[];
    readonly manifestHash: string;
    readonly participants: readonly VotingFlowParticipant[];
    readonly sessionId: string;
}): Promise<readonly SignedPayload[]> => {
    const targetDealerArtifacts =
        input.dealerArtifacts[input.complaintScenario.dealerIndex - 1];
    const targetedShare = targetDealerArtifacts.encryptedShareEntries.find(
        (entry) =>
            entry.recipientIndex === input.complaintScenario.complainantIndex,
    );

    if (targetedShare === undefined) {
        throw new Error(
            `Missing targeted encrypted share for dealer ${input.complaintScenario.dealerIndex} and complainant ${input.complaintScenario.complainantIndex}`,
        );
    }

    const complaintPayload = await signProtocolPayload(
        input.participants[input.complaintScenario.complainantIndex - 1].auth
            .privateKey,
        {
            sessionId: input.sessionId,
            manifestHash: input.manifestHash,
            phase: 2,
            participantIndex: input.complaintScenario.complainantIndex,
            messageType: 'complaint',
            dealerIndex: input.complaintScenario.dealerIndex,
            envelopeId: targetedShare.payload.payload.envelopeId,
            reason: input.complaintScenario.reason ?? 'aes-gcm-failure',
        },
    );
    const resolutionPayload = await signProtocolPayload(
        input.participants[input.complaintScenario.dealerIndex - 1].auth
            .privateKey,
        {
            sessionId: input.sessionId,
            manifestHash: input.manifestHash,
            phase: 2,
            participantIndex: input.complaintScenario.dealerIndex,
            messageType: 'complaint-resolution',
            dealerIndex: input.complaintScenario.dealerIndex,
            complainantIndex: input.complaintScenario.complainantIndex,
            envelopeId: targetedShare.payload.payload.envelopeId,
            suite: targetedShare.payload.payload.suite,
            revealedEphemeralPrivateKey: targetedShare.ephemeralPrivateKey,
        },
    );

    return [complaintPayload, resolutionPayload];
};

const createKeyDerivationConfirmations = async (
    participants: readonly VotingFlowParticipant[],
    dkgTranscript: readonly SignedPayload[],
    jointPublicKey: EncodedPoint,
    manifestHash: string,
    sessionId: string,
): Promise<readonly SignedPayload<KeyDerivationConfirmation>[]> => {
    const dkgTranscriptHash = await hashProtocolTranscript(
        dkgTranscript.map((entry) => entry.payload),
        RISTRETTO_GROUP.byteLength,
    );

    return Promise.all(
        participants.map((participant) =>
            createKeyDerivationConfirmationPayload(
                participant.auth.privateKey,
                {
                    sessionId,
                    manifestHash,
                    participantIndex: participant.index,
                    dkgTranscriptHash,
                    publicKey: jointPublicKey,
                },
            ),
        ),
    );
};

const createPhaseCheckpointPayloads = async (input: {
    readonly checkpointPhase: 0 | 1 | 2 | 3;
    readonly manifestHash: string;
    readonly participants: readonly VotingFlowParticipant[];
    readonly qualifiedParticipantIndices: readonly number[];
    readonly sessionId: string;
    readonly transcript: readonly SignedPayload[];
}): Promise<readonly SignedPayload[]> =>
    Promise.all(
        input.qualifiedParticipantIndices.map((participantIndex) =>
            createPhaseCheckpointPayload(
                input.participants[participantIndex - 1].auth.privateKey,
                {
                    checkpointPhase: input.checkpointPhase,
                    manifestHash: input.manifestHash,
                    participantIndex,
                    qualifiedParticipantIndices:
                        input.qualifiedParticipantIndices,
                    sessionId: input.sessionId,
                    transcript: input.transcript,
                },
            ),
        ),
    );

const transposeParticipantVotes = (
    participantVotes: readonly (readonly bigint[])[],
): readonly (readonly bigint[])[] =>
    Array.from(
        { length: participantVotes[0]?.length ?? 0 },
        (_value, optionOffset) =>
            participantVotes.map((participant) => participant[optionOffset]),
    );

const createBallotPayloads = async (input: {
    readonly ballotRandomness: readonly (readonly bigint[])[] | undefined;
    readonly participants: readonly VotingFlowParticipant[];
    readonly publicKey: EncodedPoint;
    readonly manifestHash: string;
    readonly participantVotes: readonly (readonly bigint[])[];
    readonly scoreRange: ScoreRange;
    readonly sessionId: string;
    readonly votingParticipantIndices: readonly number[];
}): Promise<readonly SignedPayload<BallotSubmissionPayload>[]> => {
    const payloads: SignedPayload<BallotSubmissionPayload>[] = [];
    const validValues = scoreRangeDomain(input.scoreRange);
    const additiveBound = BigInt(input.scoreRange.max);

    for (const participantIndex of input.votingParticipantIndices) {
        const votes = input.participantVotes[participantIndex - 1];

        for (
            let optionIndex = 1;
            optionIndex <= votes.length;
            optionIndex += 1
        ) {
            const vote = votes[optionIndex - 1];
            const randomness =
                input.ballotRandomness?.[participantIndex - 1]?.[
                    optionIndex - 1
                ] ?? defaultBallotRandomness(participantIndex, optionIndex);
            const ciphertext = encryptAdditiveWithRandomness(
                vote,
                input.publicKey,
                randomness,
                additiveBound,
            );
            const context: ProofContext = {
                protocolVersion: SHIPPED_PROTOCOL_VERSION,
                suiteId: RISTRETTO_GROUP.name,
                manifestHash: input.manifestHash,
                sessionId: input.sessionId,
                label: 'ballot-range-proof',
                voterIndex: participantIndex,
                optionIndex,
            };
            const proof = await createDisjunctiveProof(
                vote,
                randomness,
                ciphertext,
                input.publicKey,
                validValues,
                RISTRETTO_GROUP,
                context,
            );

            payloads.push(
                await createBallotSubmissionPayload(
                    input.participants[participantIndex - 1].auth.privateKey,
                    {
                        sessionId: input.sessionId,
                        manifestHash: input.manifestHash,
                        participantIndex,
                        optionIndex,
                        ciphertext,
                        proof,
                    },
                ),
            );
        }
    }

    return payloads;
};

export const runVotingFlowScenario = async (
    scenario: VotingFlowScenario,
): Promise<CompletedVotingFlowResult> => {
    assert(
        Number.isInteger(scenario.participantCount) &&
            scenario.participantCount >= 3,
        'Voting flow scenarios require at least three participants',
    );

    const optionList = normalizeOptionList(scenario);
    const optionCount = optionList.length;
    const scoreRange = normalizeScoreRange(scenario.scoreRange);
    const participantVotes = normalizeParticipantVotes(
        scenario,
        optionCount,
        scoreRange,
    );
    const ballotRandomness = normalizeBallotRandomness(scenario, optionCount);
    const votingParticipantIndices = normalizeParticipantIndices(
        scenario.votingParticipantIndices ??
            Array.from(
                { length: scenario.participantCount },
                (_value, index) => index + 1,
            ),
        scenario.participantCount,
        'Voting flow',
    );
    const closeParticipantIndices = normalizeParticipantIndices(
        scenario.closeParticipantIndices ?? votingParticipantIndices,
        scenario.participantCount,
        'Ballot close',
    );
    const participants = await buildParticipants(scenario.participantCount);
    const rosterHash = await hashRosterEntries(
        participants.map((participant) => ({
            participantIndex: participant.index,
            authPublicKey: participant.authPublicKey,
            transportPublicKey: participant.transportPublicKey,
        })),
    );
    const manifest = createElectionManifest({
        rosterHash,
        optionList,
        scoreRange,
    });
    const manifestHash = await hashElectionManifest(manifest);
    const threshold = majorityThreshold(scenario.participantCount);
    const sessionId = await deriveSessionId(
        manifestHash,
        rosterHash,
        scenario.sessionNonce ??
            `harness-${scenario.participantCount}-${optionCount}-${closeParticipantIndices.join('-')}`,
        scenario.timestamp ?? '2026-04-11T12:00:00Z',
    );
    const manifestPublication = await createManifestPublicationPayload(
        participants[0].auth.privateKey,
        {
            manifest,
            manifestHash,
            participantIndex: participants[0].index,
            sessionId,
        },
    );
    const registrations = await Promise.all(
        participants.map((participant) =>
            createRegistrationPayload(participant.auth.privateKey, {
                authPublicKey: participant.authPublicKey,
                manifestHash,
                participantIndex: participant.index,
                rosterHash,
                sessionId,
                transportPublicKey: participant.transportPublicKey,
            }),
        ),
    );
    const acceptances = await Promise.all(
        participants.map((participant) =>
            createManifestAcceptancePayload(participant.auth.privateKey, {
                assignedParticipantIndex: participant.index,
                manifestHash,
                participantIndex: participant.index,
                rosterHash,
                sessionId,
            }),
        ),
    );
    const dealerArtifacts = await Promise.all(
        participants.map((participant) =>
            buildDealerArtifacts(
                participant,
                participants,
                sessionId,
                manifestHash,
                rosterHash,
                threshold,
                scenario.dkgComplaint,
            ),
        ),
    );
    const complaintScenario = scenario.dkgComplaint;
    const qualifiedParticipantIndices =
        complaintScenario?.outcome === 'accepted'
            ? participants
                  .map((participant) => participant.index)
                  .filter(
                      (participantIndex) =>
                          participantIndex !== complaintScenario.dealerIndex,
                  )
            : participants.map((participant) => participant.index);
    const qualifiedParticipantIndexSet = new Set(qualifiedParticipantIndices);
    const qualifiedDealerCommitments = dealerArtifacts
        .map((dealer, offset) => ({
            dealerIndex: offset + 1,
            commitments: dealer.feldmanCommitments,
        }))
        .filter((dealer) =>
            qualifiedParticipantIndexSet.has(dealer.dealerIndex),
        );
    const jointPublicKey = deriveJointPublicKey(
        qualifiedDealerCommitments,
        RISTRETTO_GROUP,
    );
    const dkgTranscriptWithoutConfirmations: SignedPayload[] = [
        manifestPublication,
        ...registrations,
        ...acceptances,
    ];

    if (scenario.includePhaseCheckpoints === true) {
        dkgTranscriptWithoutConfirmations.push(
            ...(await createPhaseCheckpointPayloads({
                checkpointPhase: 0,
                manifestHash,
                participants,
                qualifiedParticipantIndices: participants.map(
                    (participant) => participant.index,
                ),
                sessionId,
                transcript: dkgTranscriptWithoutConfirmations,
            })),
        );
    }

    dkgTranscriptWithoutConfirmations.push(
        ...dealerArtifacts.map((dealer) => dealer.pedersenPayload),
        ...dealerArtifacts.flatMap((dealer) => dealer.encryptedSharePayloads),
    );

    if (scenario.includePhaseCheckpoints === true) {
        dkgTranscriptWithoutConfirmations.push(
            ...(await createPhaseCheckpointPayloads({
                checkpointPhase: 1,
                manifestHash,
                participants,
                qualifiedParticipantIndices: participants.map(
                    (participant) => participant.index,
                ),
                sessionId,
                transcript: dkgTranscriptWithoutConfirmations,
            })),
        );
    }

    if (scenario.dkgComplaint !== undefined) {
        dkgTranscriptWithoutConfirmations.push(
            ...(await createComplaintPayloads({
                complaintScenario: scenario.dkgComplaint,
                dealerArtifacts,
                manifestHash,
                participants,
                sessionId,
            })),
        );
    }

    if (scenario.includePhaseCheckpoints === true) {
        dkgTranscriptWithoutConfirmations.push(
            ...(await createPhaseCheckpointPayloads({
                checkpointPhase: 2,
                manifestHash,
                participants,
                qualifiedParticipantIndices,
                sessionId,
                transcript: dkgTranscriptWithoutConfirmations,
            })),
        );
    }

    dkgTranscriptWithoutConfirmations.push(
        ...dealerArtifacts.map((dealer) => dealer.feldmanPayload),
    );

    if (scenario.includePhaseCheckpoints === true) {
        dkgTranscriptWithoutConfirmations.push(
            ...(await createPhaseCheckpointPayloads({
                checkpointPhase: 3,
                manifestHash,
                participants,
                qualifiedParticipantIndices,
                sessionId,
                transcript: dkgTranscriptWithoutConfirmations,
            })),
        );
    }

    const confirmations = await createKeyDerivationConfirmations(
        participants.filter((participant) =>
            qualifiedParticipantIndexSet.has(participant.index),
        ),
        dkgTranscriptWithoutConfirmations,
        jointPublicKey,
        manifestHash,
        sessionId,
    );
    const dkgTranscript = [
        ...dkgTranscriptWithoutConfirmations,
        ...confirmations,
    ] as const;
    const finalShares = participants.map((participant) => ({
        index: participant.index,
        value: modQ(
            dealerArtifacts.reduce(
                (sum, dealer, dealerOffset) =>
                    qualifiedParticipantIndexSet.has(dealerOffset + 1)
                        ? sum + dealer.shares[participant.index - 1].secretValue
                        : sum,
                0n,
            ),
            RISTRETTO_GROUP.q,
        ),
    }));
    const ballotPayloads = await createBallotPayloads({
        ballotRandomness,
        participants,
        publicKey: jointPublicKey,
        manifestHash,
        participantVotes,
        scoreRange,
        sessionId,
        votingParticipantIndices,
    });
    const ballotClosePayload = await createBallotClosePayload(
        participants[0].auth.privateKey,
        {
            sessionId,
            manifestHash,
            participantIndex: participants[0].index,
            countedParticipantIndices: closeParticipantIndices,
        },
    );
    const countedBallotPayloads = ballotPayloads.filter((payload) =>
        closeParticipantIndices.includes(payload.payload.participantIndex),
    );
    const verifiedBallots = await verifyBallotSubmissionPayloadsByOption({
        ballotPayloads: countedBallotPayloads,
        publicKey: jointPublicKey,
        manifest,
        sessionId,
    });
    const preferredDecryptionParticipants = closeParticipantIndices.filter(
        (participantIndex) =>
            qualifiedParticipantIndexSet.has(participantIndex),
    );
    const selectedParticipants = (
        preferredDecryptionParticipants.length >= threshold
            ? preferredDecryptionParticipants
            : qualifiedParticipantIndices
    ).slice(0, threshold);
    const decryptionSharePayloads: SignedPayload<DecryptionSharePayload>[] = [];
    const tallyPublications: SignedPayload<TallyPublicationPayload>[] = [];

    for (const optionBallots of verifiedBallots) {
        const preparedAggregate = prepareAggregateForDecryption({
            aggregate: optionBallots.aggregate,
            publicKey: jointPublicKey,
            protocolVersion: SHIPPED_PROTOCOL_VERSION,
            manifestHash,
            sessionId,
            optionIndex: optionBallots.optionIndex,
        });
        const optionSharePayloads = await Promise.all(
            selectedParticipants.map(async (participantIndex) => {
                const share = finalShares[participantIndex - 1];
                const verifiedShare = createDecryptionShare(
                    preparedAggregate.ciphertext,
                    share,
                );
                const statement: DLEQStatement = {
                    publicKey: deriveTranscriptVerificationKey(
                        qualifiedDealerCommitments,
                        participantIndex,
                        RISTRETTO_GROUP,
                    ),
                    ciphertext: preparedAggregate.ciphertext,
                    decryptionShare: verifiedShare.value,
                };
                const context: ProofContext = {
                    protocolVersion: SHIPPED_PROTOCOL_VERSION,
                    suiteId: RISTRETTO_GROUP.name,
                    manifestHash,
                    sessionId,
                    label: 'decryption-share-dleq',
                    participantIndex,
                    optionIndex: optionBallots.optionIndex,
                };
                const proof = await createDLEQProof(
                    share.value,
                    statement,
                    RISTRETTO_GROUP,
                    context,
                );

                return {
                    payload: await createDecryptionSharePayload(
                        participants[participantIndex - 1].auth.privateKey,
                        {
                            sessionId,
                            manifestHash,
                            participantIndex,
                            optionIndex: optionBallots.optionIndex,
                            transcriptHash:
                                optionBallots.aggregate.transcriptHash,
                            ballotCount: optionBallots.aggregate.ballotCount,
                            decryptionShare: verifiedShare.value,
                            proof,
                        },
                    ),
                    share: verifiedShare,
                };
            }),
        );
        const tally = combineDecryptionShares(
            preparedAggregate.ciphertext,
            optionSharePayloads.map((entry) => entry.share),
            BigInt(optionBallots.aggregate.ballotCount) *
                BigInt(scoreRange.max),
        );

        decryptionSharePayloads.push(
            ...optionSharePayloads.map((entry) => entry.payload),
        );
        tallyPublications.push(
            await createTallyPublicationPayload(
                participants[0].auth.privateKey,
                {
                    sessionId,
                    manifestHash,
                    participantIndex: participants[0].index,
                    optionIndex: optionBallots.optionIndex,
                    transcriptHash: optionBallots.aggregate.transcriptHash,
                    ballotCount: optionBallots.aggregate.ballotCount,
                    tally,
                    decryptionParticipantIndices: selectedParticipants,
                },
            ),
        );
    }

    const verified = await verifyElectionCeremony({
        manifest,
        sessionId,
        dkgTranscript,
        ballotPayloads,
        ballotClosePayload,
        decryptionSharePayloads,
        tallyPublications,
    });
    const optionVotesByOption = transposeParticipantVotes(participantVotes);
    const expectedTallies = optionVotesByOption.map((optionVotes) =>
        closeParticipantIndices.reduce(
            (sum, participantIndex) => sum + optionVotes[participantIndex - 1],
            0n,
        ),
    );

    return {
        ballotClosePayload,
        ballotPayloads,
        countedParticipantIndices: closeParticipantIndices,
        decryptionSharePayloads,
        dkgTranscript,
        expectedTallies,
        finalShares,
        manifest,
        manifestHash,
        participants,
        participantVotes,
        qualifiedParticipantIndices,
        rosterHash,
        sessionId,
        tallyPublications,
        threshold,
        verified,
        votingParticipantIndices,
    };
};
