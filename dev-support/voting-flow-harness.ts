import { TextEncoder } from 'node:util';

import {
    combineDecryptionShares,
    createBallotClosePayload,
    createBallotSubmissionPayload,
    createDLEQProof,
    createDecryptionSharePayload,
    createDisjunctiveProof,
    createElectionManifest,
    createEncryptedDualSharePayload,
    createFeldmanCommitmentPayload,
    createKeyDerivationConfirmationPayload,
    createManifestAcceptancePayload,
    createManifestPublicationPayload,
    createPedersenCommitmentPayload,
    createRegistrationPayload,
    createSchnorrProof,
    createTallyPublicationPayload,
    createVerifiedDecryptionShare,
    deriveJointPublicKey,
    derivePedersenShares,
    deriveSessionId,
    deriveTranscriptVerificationKey,
    encodePedersenShareEnvelope,
    encryptAdditiveWithRandomness,
    encryptEnvelope,
    exportAuthPublicKey,
    exportTransportPublicKey,
    generateAuthKeyPair,
    generateFeldmanCommitments,
    generatePedersenCommitments,
    generateTransportKeyPair,
    hashElectionManifest,
    hashProtocolTranscript,
    hashRosterEntries,
    majorityThreshold,
    modQ,
    RISTRETTO_GROUP,
    scoreVotingDomain,
    SHIPPED_PROTOCOL_VERSION,
    verifyBallotSubmissionPayloadsByOption,
    verifyElectionCeremonyDetailed,
    type BallotSubmissionPayload,
    type DecryptionSharePayload,
    type DLEQStatement,
    type ElectionManifest,
    type EncodedPoint,
    type KeyAgreementSuite,
    type KeyDerivationConfirmation,
    type ProofContext,
    type SignedPayload,
    type TallyPublicationPayload,
} from 'threshold-elgamal';

type HarnessParticipant = {
    readonly auth: CryptoKeyPair;
    readonly authPublicKey: string;
    readonly index: number;
    readonly transport: Awaited<ReturnType<typeof generateTransportKeyPair>>;
    readonly transportPublicKey: string;
};

type DealerArtifacts = {
    readonly encryptedSharePayloads: readonly SignedPayload[];
    readonly feldmanCommitments: readonly EncodedPoint[];
    readonly feldmanPayload: SignedPayload;
    readonly pedersenPayload: SignedPayload;
    readonly shares: ReturnType<typeof derivePedersenShares>;
};

export type VotingFlowScenario = {
    readonly closeParticipantIndices?: readonly number[];
    readonly optionCount?: number;
    readonly optionList?: readonly string[];
    readonly participantCount: number;
    readonly transportSuite?: KeyAgreementSuite;
    readonly votingParticipantIndices?: readonly number[];
};

export type CompletedVotingFlowResult = {
    readonly dkgTranscript: readonly SignedPayload[];
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
    readonly threshold: number;
    readonly verified: Awaited<
        ReturnType<typeof verifyElectionCeremonyDetailed>
    >;
};

const assert = (condition: boolean, message: string): void => {
    if (!condition) {
        throw new Error(message);
    }
};

const buildParticipants = async (
    participantCount: number,
    suite: KeyAgreementSuite,
): Promise<readonly HarnessParticipant[]> =>
    Promise.all(
        Array.from({ length: participantCount }, async (_value, offset) => {
            const index = offset + 1;
            const auth = await generateAuthKeyPair({ extractable: true });
            const transport = await generateTransportKeyPair({
                suite,
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

const buildOptionVotes = (
    participantCount: number,
    optionCount: number,
): readonly (readonly bigint[])[] =>
    Array.from({ length: optionCount }, (_value, optionOffset) =>
        Array.from({ length: participantCount }, (_entry, participantOffset) =>
            BigInt(((participantOffset + optionOffset * 2) % 10) + 1),
        ),
    );

const buildDealerArtifacts = async (
    participant: HarnessParticipant,
    participants: readonly HarnessParticipant[],
    sessionId: string,
    manifestHash: string,
    rosterHash: string,
    threshold: number,
): Promise<DealerArtifacts> => {
    const group = RISTRETTO_GROUP;
    const secretPolynomial = buildPolynomial(
        participant.index,
        threshold,
        group.q,
        7,
    );
    const blindingPolynomial = buildPolynomial(
        participant.index,
        threshold,
        group.q,
        43,
    );
    const pedersenCommitments = generatePedersenCommitments(
        secretPolynomial,
        blindingPolynomial,
        group,
    );
    const shares = derivePedersenShares(
        secretPolynomial,
        blindingPolynomial,
        participants.length,
        group.q,
    );
    const feldmanCommitments = generateFeldmanCommitments(
        secretPolynomial,
        group,
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
                suiteId: group.name,
                manifestHash,
                sessionId,
                label: 'feldman-coefficient-proof',
                participantIndex: participant.index,
                coefficientIndex,
            };
            const proof = await createSchnorrProof(
                coefficient,
                feldmanCommitments.commitments[offset],
                group,
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
    const encryptedSharePayloads = await Promise.all(
        participants
            .filter((recipient) => recipient.index !== participant.index)
            .map(async (recipient) => {
                const share = shares[recipient.index - 1];
                const plaintext = new TextEncoder().encode(
                    encodePedersenShareEnvelope(share, group.byteLength),
                );
                const { envelope } = await encryptEnvelope(
                    plaintext,
                    recipient.transportPublicKey as never,
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

                return createEncryptedDualSharePayload(
                    participant.auth.privateKey,
                    {
                        sessionId,
                        manifestHash,
                        participantIndex: participant.index,
                        recipientIndex: recipient.index,
                        envelopeId: envelope.envelopeId,
                        suite: envelope.suite,
                        ephemeralPublicKey: envelope.ephemeralPublicKey,
                        iv: envelope.iv,
                        ciphertext: envelope.ciphertext,
                    },
                );
            }),
    );

    return {
        encryptedSharePayloads,
        feldmanCommitments: feldmanCommitments.commitments,
        feldmanPayload,
        pedersenPayload,
        shares,
    };
};

const createKeyDerivationConfirmations = async (
    participants: readonly HarnessParticipant[],
    dkgTranscript: readonly SignedPayload[],
    derivedPublicKey: EncodedPoint,
    manifestHash: string,
    sessionId: string,
): Promise<readonly SignedPayload<KeyDerivationConfirmation>[]> => {
    const qualHash = await hashProtocolTranscript(
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
                    qualHash,
                    publicKey: derivedPublicKey,
                },
            ),
        ),
    );
};

const createBallotPayloads = async (input: {
    readonly participants: readonly HarnessParticipant[];
    readonly publicKey: EncodedPoint;
    readonly manifestHash: string;
    readonly optionVotes: readonly (readonly bigint[])[];
    readonly sessionId: string;
    readonly votingParticipantIndices: readonly number[];
}): Promise<readonly SignedPayload<BallotSubmissionPayload>[]> => {
    const payloads: SignedPayload<BallotSubmissionPayload>[] = [];
    const validValues = scoreVotingDomain();

    for (const participantIndex of input.votingParticipantIndices) {
        for (
            let optionIndex = 1;
            optionIndex <= input.optionVotes.length;
            optionIndex += 1
        ) {
            const vote =
                input.optionVotes[optionIndex - 1][participantIndex - 1];
            const randomness = BigInt(
                1000 + participantIndex * 97 + optionIndex * 31,
            );
            const ciphertext = encryptAdditiveWithRandomness(
                vote,
                input.publicKey,
                randomness,
                10n,
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

    const transportSuite = scenario.transportSuite ?? 'P-256';
    const participants = await buildParticipants(
        scenario.participantCount,
        transportSuite,
    );
    const rosterHash = await hashRosterEntries(
        participants.map((participant) => ({
            participantIndex: participant.index,
            authPublicKey: participant.authPublicKey as never,
            transportPublicKey: participant.transportPublicKey as never,
        })),
    );
    const optionCount =
        scenario.optionList?.length ?? Math.max(1, scenario.optionCount ?? 1);
    const manifest = createElectionManifest({
        rosterHash,
        optionList:
            scenario.optionList ??
            Array.from(
                { length: optionCount },
                (_value, index) => `Option ${index + 1}`,
            ),
    });
    const manifestHash = await hashElectionManifest(manifest);
    const threshold = majorityThreshold(scenario.participantCount);
    const votingParticipantIndices =
        scenario.votingParticipantIndices ??
        Array.from(
            { length: scenario.participantCount },
            (_value, index) => index + 1,
        );
    const closeParticipantIndices =
        scenario.closeParticipantIndices ?? votingParticipantIndices;
    const sessionId = await deriveSessionId(
        manifestHash,
        rosterHash,
        `benchmark-${scenario.participantCount}-${optionCount}-${closeParticipantIndices.join('-')}`,
        '2026-04-11T12:00:00Z',
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
                authPublicKey: participant.authPublicKey as never,
                manifestHash,
                participantIndex: participant.index,
                rosterHash,
                sessionId,
                transportPublicKey: participant.transportPublicKey as never,
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
            ),
        ),
    );
    const derivedPublicKey = deriveJointPublicKey(
        dealerArtifacts.map((dealer, offset) => ({
            dealerIndex: offset + 1,
            commitments: dealer.feldmanCommitments,
        })),
        RISTRETTO_GROUP,
    );
    const dkgTranscriptWithoutConfirmations = [
        manifestPublication,
        ...registrations,
        ...acceptances,
        ...dealerArtifacts.map((dealer) => dealer.pedersenPayload),
        ...dealerArtifacts.flatMap((dealer) => dealer.encryptedSharePayloads),
        ...dealerArtifacts.map((dealer) => dealer.feldmanPayload),
    ] as const;
    const confirmations = await createKeyDerivationConfirmations(
        participants,
        dkgTranscriptWithoutConfirmations,
        derivedPublicKey,
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
                (sum, dealer) =>
                    sum + dealer.shares[participant.index - 1].secretValue,
                0n,
            ),
            RISTRETTO_GROUP.q,
        ),
    }));
    const optionVotes = buildOptionVotes(
        scenario.participantCount,
        optionCount,
    );
    const ballotPayloads = await createBallotPayloads({
        participants,
        publicKey: derivedPublicKey,
        manifestHash,
        optionVotes,
        sessionId,
        votingParticipantIndices,
    });
    const ballotClosePayload = await createBallotClosePayload(
        participants[0].auth.privateKey,
        {
            sessionId,
            manifestHash,
            participantIndex: participants[0].index,
            includedParticipantIndices: closeParticipantIndices,
        },
    );
    const countedBallotPayloads = ballotPayloads.filter((payload) =>
        closeParticipantIndices.includes(payload.payload.participantIndex),
    );
    const verifiedBallots = await verifyBallotSubmissionPayloadsByOption({
        ballotPayloads: countedBallotPayloads,
        publicKey: derivedPublicKey,
        manifest,
        sessionId,
    });
    const selectedParticipants = closeParticipantIndices.slice(0, threshold);
    const decryptionSharePayloads: SignedPayload<DecryptionSharePayload>[] = [];
    const tallyPublications: SignedPayload<TallyPublicationPayload>[] = [];

    for (const optionBallots of verifiedBallots) {
        const optionSharePayloads = await Promise.all(
            selectedParticipants.map(async (participantIndex) => {
                const share = finalShares[participantIndex - 1];
                const verifiedShare = createVerifiedDecryptionShare(
                    optionBallots.aggregate,
                    share,
                );
                const statement: DLEQStatement = {
                    publicKey: deriveTranscriptVerificationKey(
                        dealerArtifacts.map((dealer, offset) => ({
                            dealerIndex: offset + 1,
                            commitments: dealer.feldmanCommitments,
                        })),
                        participantIndex,
                        RISTRETTO_GROUP,
                    ),
                    ciphertext: optionBallots.aggregate.ciphertext,
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
            optionBallots.aggregate.ciphertext,
            optionSharePayloads.map((entry) => entry.share),
            BigInt(optionBallots.aggregate.ballotCount) * 10n,
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

    const verified = await verifyElectionCeremonyDetailed({
        manifest,
        sessionId,
        dkgTranscript,
        ballotPayloads,
        ballotClosePayload,
        decryptionSharePayloads,
        tallyPublications,
    });

    return {
        dkgTranscript,
        manifest,
        sessionId,
        threshold,
        verified,
    };
};
