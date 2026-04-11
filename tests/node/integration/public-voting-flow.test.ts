import { TextEncoder } from 'node:util';

import { beforeAll, describe, expect, it } from 'vitest';

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
    createManifestAcceptancePayload,
    createManifestPublicationPayload,
    createKeyDerivationConfirmationPayload,
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
    signProtocolPayload,
    verifyBallotSubmissionPayloadsByOption,
    verifyDKGTranscript,
    verifyDLEQProof,
    verifyDisjunctiveProof,
    verifyElectionCeremonyDetailed,
    verifyFeldmanShare,
    verifyPedersenShare,
    verifySchnorrProof,
    type BallotClosePayload,
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

const fixtureTimeoutMs = 240_000;

type TestParticipant = {
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

type CeremonyFixture = {
    readonly countedParticipantIndices: readonly number[];
    readonly dkgTranscript: readonly SignedPayload[];
    readonly ballotPayloads: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly ballotClosePayload: SignedPayload<BallotClosePayload>;
    readonly decryptionSharePayloads: readonly SignedPayload<DecryptionSharePayload>[];
    readonly expectedTallies: readonly bigint[];
    readonly finalShares: readonly {
        readonly index: number;
        readonly value: bigint;
    }[];
    readonly manifest: ElectionManifest;
    readonly manifestHash: string;
    readonly participants: readonly TestParticipant[];
    readonly sessionId: string;
    readonly tallyPublications: readonly SignedPayload<TallyPublicationPayload>[];
    readonly threshold: number;
    readonly verified: Awaited<
        ReturnType<typeof verifyElectionCeremonyDetailed>
    >;
    readonly votingParticipantIndices: readonly number[];
};

const buildParticipants = async (
    participantCount: number,
    suite: KeyAgreementSuite = 'P-256',
): Promise<readonly TestParticipant[]> =>
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
    participant: TestParticipant,
    participants: readonly TestParticipant[],
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

    shares.forEach((share) => {
        expect(verifyPedersenShare(share, pedersenCommitments, group)).toBe(
            true,
        );
        expect(
            verifyFeldmanShare(
                { index: share.index, value: share.secretValue },
                feldmanCommitments,
                group,
            ),
        ).toBe(true);
    });

    const pedersenPayload = await createPedersenCommitmentPayload(
        participant.auth.privateKey,
        {
            sessionId,
            manifestHash,
            participantIndex: participant.index,
            commitments: pedersenCommitments.commitments,
        },
    );

    const proofEntries = await Promise.all(
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

            expect(
                await verifySchnorrProof(
                    proof,
                    feldmanCommitments.commitments[offset],
                    group,
                    context,
                ),
            ).toBe(true);

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
            proofs: proofEntries,
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
    participants: readonly TestParticipant[],
    dkgTranscript: readonly SignedPayload[],
    derivedPublicKey: EncodedPoint,
    manifestHash: string,
    sessionId: string,
): Promise<readonly SignedPayload<KeyDerivationConfirmation>[]> => {
    const group = RISTRETTO_GROUP;
    const qualHash = await hashProtocolTranscript(
        dkgTranscript.map((entry) => entry.payload),
        group.byteLength,
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
    readonly participants: readonly TestParticipant[];
    readonly publicKey: EncodedPoint;
    readonly manifestHash: string;
    readonly optionVotes: readonly (readonly bigint[])[];
    readonly sessionId: string;
    readonly votingParticipantIndices: readonly number[];
}): Promise<readonly SignedPayload<BallotSubmissionPayload>[]> => {
    const group = RISTRETTO_GROUP;
    const validValues = scoreVotingDomain();
    const payloads: SignedPayload<BallotSubmissionPayload>[] = [];

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
                suiteId: group.name,
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
                group,
                context,
            );

            expect(
                await verifyDisjunctiveProof(
                    proof,
                    ciphertext,
                    input.publicKey,
                    validValues,
                    group,
                    context,
                ),
            ).toBe(true);

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

const buildCeremonyFixture = async (input: {
    readonly closeParticipantIndices: readonly number[];
    readonly optionCount: number;
    readonly participantCount: number;
    readonly votingParticipantIndices: readonly number[];
}): Promise<CeremonyFixture> => {
    const participants = await buildParticipants(input.participantCount);
    const rosterHash = await hashRosterEntries(
        participants.map((participant) => ({
            participantIndex: participant.index,
            authPublicKey: participant.authPublicKey as never,
            transportPublicKey: participant.transportPublicKey as never,
        })),
    );
    const manifest = createElectionManifest({
        rosterHash,
        optionList: Array.from(
            { length: input.optionCount },
            (_value, index) => `Option ${index + 1}`,
        ),
    });
    const manifestHash = await hashElectionManifest(manifest);
    const threshold = majorityThreshold(input.participantCount);
    const sessionId = await deriveSessionId(
        manifestHash,
        rosterHash,
        `nonce-${input.participantCount}-${input.optionCount}-${input.closeParticipantIndices.join('-')}`,
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
    const normalizedFeldmanCommitments = dealerArtifacts.map(
        (dealer, offset) => ({
            dealerIndex: offset + 1,
            commitments: dealer.feldmanCommitments,
        }),
    );
    const derivedPublicKey = deriveJointPublicKey(
        normalizedFeldmanCommitments,
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
    const dkg = await verifyDKGTranscript({
        transcript: dkgTranscript,
        manifest,
        sessionId,
    });

    const group = RISTRETTO_GROUP;
    const finalShares = participants.map((participant) => ({
        index: participant.index,
        value: modQ(
            dealerArtifacts.reduce(
                (sum, dealer) =>
                    sum + dealer.shares[participant.index - 1].secretValue,
                0n,
            ),
            group.q,
        ),
    }));

    const optionVotes = buildOptionVotes(
        input.participantCount,
        input.optionCount,
    );
    const ballotPayloads = await createBallotPayloads({
        participants,
        publicKey: dkg.derivedPublicKey,
        manifestHash,
        optionVotes,
        sessionId,
        votingParticipantIndices: input.votingParticipantIndices,
    });
    const ballotClosePayload = await createBallotClosePayload(
        participants[0].auth.privateKey,
        {
            sessionId,
            manifestHash,
            participantIndex: participants[0].index,
            includedParticipantIndices: input.closeParticipantIndices,
        },
    );

    const countedBallotPayloads = ballotPayloads.filter((payload) =>
        input.closeParticipantIndices.includes(
            payload.payload.participantIndex,
        ),
    );
    const verifiedBallots = await verifyBallotSubmissionPayloadsByOption({
        ballotPayloads: countedBallotPayloads,
        publicKey: dkg.derivedPublicKey,
        manifest,
        sessionId,
    });
    const selectedDecryptionIndices = input.closeParticipantIndices.slice(
        0,
        threshold,
    );
    const decryptionSharePayloads: SignedPayload<DecryptionSharePayload>[] = [];
    const tallyPublications: SignedPayload<TallyPublicationPayload>[] = [];
    const expectedTallies: bigint[] = [];

    for (const optionBallots of verifiedBallots) {
        const optionShares = await Promise.all(
            selectedDecryptionIndices.map(async (participantIndex) => {
                const share = finalShares.find(
                    (entry) => entry.index === participantIndex,
                );
                if (share === undefined) {
                    throw new Error(
                        `Missing final share for participant ${participantIndex}`,
                    );
                }

                const verifiedShare = createVerifiedDecryptionShare(
                    optionBallots.aggregate,
                    share,
                );
                const statement: DLEQStatement = {
                    publicKey: deriveTranscriptVerificationKey(
                        dkg.feldmanCommitments,
                        participantIndex,
                        group,
                    ),
                    ciphertext: optionBallots.aggregate.ciphertext,
                    decryptionShare: verifiedShare.value,
                };
                const context: ProofContext = {
                    protocolVersion: SHIPPED_PROTOCOL_VERSION,
                    suiteId: group.name,
                    manifestHash,
                    sessionId,
                    label: 'decryption-share-dleq',
                    participantIndex,
                    optionIndex: optionBallots.optionIndex,
                };
                const proof = await createDLEQProof(
                    share.value,
                    statement,
                    group,
                    context,
                );

                expect(
                    await verifyDLEQProof(proof, statement, group, context),
                ).toBe(true);

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
            optionShares.map((entry) => entry.share),
            BigInt(optionBallots.aggregate.ballotCount) * 10n,
        );
        const expectedTally = input.closeParticipantIndices.reduce(
            (sum, participantIndex) =>
                sum +
                optionVotes[optionBallots.optionIndex - 1][
                    participantIndex - 1
                ],
            0n,
        );
        expectedTallies.push(expectedTally);
        expect(tally).toBe(expectedTally);

        decryptionSharePayloads.push(
            ...optionShares.map((entry) => entry.payload),
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
                    decryptionParticipantIndices: selectedDecryptionIndices,
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
        countedParticipantIndices: input.closeParticipantIndices,
        dkgTranscript,
        ballotPayloads,
        ballotClosePayload,
        decryptionSharePayloads,
        expectedTallies,
        finalShares,
        manifest,
        manifestHash,
        participants,
        sessionId,
        tallyPublications,
        threshold,
        verified,
        votingParticipantIndices: input.votingParticipantIndices,
    };
};

describe('public voting flow', () => {
    let allTenFixture: CeremonyFixture;
    let nineOfTenFixture: CeremonyFixture;
    let thresholdOnlyFixture: CeremonyFixture;
    let threeParticipantFixture: CeremonyFixture;

    beforeAll(async () => {
        allTenFixture = await buildCeremonyFixture({
            participantCount: 10,
            optionCount: 8,
            votingParticipantIndices: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
            closeParticipantIndices: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
        });
        nineOfTenFixture = await buildCeremonyFixture({
            participantCount: 10,
            optionCount: 8,
            votingParticipantIndices: [1, 2, 3, 4, 5, 6, 7, 8, 9],
            closeParticipantIndices: [1, 2, 3, 4, 5, 6, 7, 8, 9],
        });
        thresholdOnlyFixture = await buildCeremonyFixture({
            participantCount: 10,
            optionCount: 8,
            votingParticipantIndices: [1, 2, 3, 4, 5],
            closeParticipantIndices: [1, 2, 3, 4, 5],
        });
        threeParticipantFixture = await buildCeremonyFixture({
            participantCount: 3,
            optionCount: 2,
            votingParticipantIndices: [1, 2, 3],
            closeParticipantIndices: [1, 2, 3],
        });
    }, fixtureTimeoutMs);

    it('verifies a full 10-participant ceremony when all participants vote', () => {
        expect(allTenFixture.threshold).toBe(5);
        expect(allTenFixture.verified.dkg.participantCount).toBe(10);
        expect(allTenFixture.verified.dkg.threshold).toBe(5);
        expect(allTenFixture.verified.countedParticipantIndices).toEqual([
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
        ]);
        expect(allTenFixture.verified.excludedParticipantIndices).toEqual([]);
        expect(
            allTenFixture.verified.perOptionAcceptedCounts.map(
                (entry) => entry.acceptedCount,
            ),
        ).toEqual(Array.from({ length: 8 }, () => 10));
        expect(
            allTenFixture.verified.perOptionTallies.map((entry) => entry.tally),
        ).toEqual(allTenFixture.expectedTallies);
        expect(
            allTenFixture.verified.boardAudit.ballotClose.acceptedPayloads,
        ).toHaveLength(1);
    });

    it('verifies a 10-participant ceremony when one participant never posts a ballot', () => {
        expect(nineOfTenFixture.verified.countedParticipantIndices).toEqual([
            1, 2, 3, 4, 5, 6, 7, 8, 9,
        ]);
        expect(nineOfTenFixture.verified.excludedParticipantIndices).toEqual(
            [],
        );
        expect(
            nineOfTenFixture.verified.perOptionAcceptedCounts.map(
                (entry) => entry.acceptedCount,
            ),
        ).toEqual(Array.from({ length: 8 }, () => 9));
        expect(
            nineOfTenFixture.verified.perOptionTallies.map(
                (entry) => entry.tally,
            ),
        ).toEqual(nineOfTenFixture.expectedTallies);
    });

    it('verifies a 10-participant ceremony when the organizer closes at the majority threshold', () => {
        expect(thresholdOnlyFixture.threshold).toBe(5);
        expect(thresholdOnlyFixture.verified.countedParticipantIndices).toEqual(
            [1, 2, 3, 4, 5],
        );
        expect(
            thresholdOnlyFixture.verified.excludedParticipantIndices,
        ).toEqual([]);
        expect(
            thresholdOnlyFixture.verified.perOptionAcceptedCounts.map(
                (entry) => entry.acceptedCount,
            ),
        ).toEqual(Array.from({ length: 8 }, () => 5));
        expect(
            thresholdOnlyFixture.verified.perOptionTallies.map(
                (entry) => entry.tally,
            ),
        ).toEqual(thresholdOnlyFixture.expectedTallies);
    });

    it('verifies a 3-participant ceremony with the derived 2-of-3 majority threshold', () => {
        expect(threeParticipantFixture.threshold).toBe(2);
        expect(threeParticipantFixture.verified.dkg.participantCount).toBe(3);
        expect(threeParticipantFixture.verified.dkg.threshold).toBe(2);
        expect(
            threeParticipantFixture.verified.countedParticipantIndices,
        ).toEqual([1, 2, 3]);
        expect(
            threeParticipantFixture.verified.perOptionAcceptedCounts.map(
                (entry) => entry.acceptedCount,
            ),
        ).toEqual([3, 3]);
        expect(
            threeParticipantFixture.verified.perOptionTallies.map(
                (entry) => entry.tally,
            ),
        ).toEqual(threeParticipantFixture.expectedTallies);
    });

    it('rejects ballot close payloads signed by a non-organizer', async () => {
        const forgedBallotClosePayload = await signProtocolPayload(
            allTenFixture.participants[1].auth.privateKey,
            {
                sessionId: allTenFixture.sessionId,
                manifestHash: allTenFixture.manifestHash,
                phase: 6,
                participantIndex: allTenFixture.participants[1].index,
                messageType: 'ballot-close',
                includedParticipantIndices:
                    allTenFixture.countedParticipantIndices,
            },
        );

        await expect(
            verifyElectionCeremonyDetailed({
                manifest: allTenFixture.manifest,
                sessionId: allTenFixture.sessionId,
                dkgTranscript: allTenFixture.dkgTranscript,
                ballotPayloads: allTenFixture.ballotPayloads,
                ballotClosePayload: forgedBallotClosePayload,
                decryptionSharePayloads: allTenFixture.decryptionSharePayloads,
                tallyPublications: allTenFixture.tallyPublications,
            }),
        ).rejects.toThrow('Ballot close must be signed by organizer 1');
    });

    it('rejects ballot close payloads with duplicate or unsorted participant indices', async () => {
        const duplicateBallotClosePayload = await signProtocolPayload(
            allTenFixture.participants[0].auth.privateKey,
            {
                sessionId: allTenFixture.sessionId,
                manifestHash: allTenFixture.manifestHash,
                phase: 6,
                participantIndex: allTenFixture.participants[0].index,
                messageType: 'ballot-close',
                includedParticipantIndices: [1, 2, 2, 3, 4, 5],
            },
        );
        const unsortedBallotClosePayload = await signProtocolPayload(
            thresholdOnlyFixture.participants[0].auth.privateKey,
            {
                sessionId: thresholdOnlyFixture.sessionId,
                manifestHash: thresholdOnlyFixture.manifestHash,
                phase: 6,
                participantIndex: thresholdOnlyFixture.participants[0].index,
                messageType: 'ballot-close',
                includedParticipantIndices: [1, 3, 2, 4, 5],
            },
        );

        await expect(
            verifyElectionCeremonyDetailed({
                manifest: allTenFixture.manifest,
                sessionId: allTenFixture.sessionId,
                dkgTranscript: allTenFixture.dkgTranscript,
                ballotPayloads: allTenFixture.ballotPayloads,
                ballotClosePayload: duplicateBallotClosePayload,
                decryptionSharePayloads: allTenFixture.decryptionSharePayloads,
                tallyPublications: allTenFixture.tallyPublications,
            }),
        ).rejects.toThrow('Ballot close participant indices must be unique');
        await expect(
            verifyElectionCeremonyDetailed({
                manifest: thresholdOnlyFixture.manifest,
                sessionId: thresholdOnlyFixture.sessionId,
                dkgTranscript: thresholdOnlyFixture.dkgTranscript,
                ballotPayloads: thresholdOnlyFixture.ballotPayloads,
                ballotClosePayload: unsortedBallotClosePayload,
                decryptionSharePayloads:
                    thresholdOnlyFixture.decryptionSharePayloads,
                tallyPublications: thresholdOnlyFixture.tallyPublications,
            }),
        ).rejects.toThrow(
            'Ballot close participant indices must be strictly increasing',
        );
    });

    it('rejects ballot close payloads that include fewer than the derived threshold participants', async () => {
        const belowThresholdBallotClosePayload = await signProtocolPayload(
            thresholdOnlyFixture.participants[0].auth.privateKey,
            {
                sessionId: thresholdOnlyFixture.sessionId,
                manifestHash: thresholdOnlyFixture.manifestHash,
                phase: 6,
                participantIndex: thresholdOnlyFixture.participants[0].index,
                messageType: 'ballot-close',
                includedParticipantIndices: [1, 2, 3, 4],
            },
        );

        await expect(
            verifyElectionCeremonyDetailed({
                manifest: thresholdOnlyFixture.manifest,
                sessionId: thresholdOnlyFixture.sessionId,
                dkgTranscript: thresholdOnlyFixture.dkgTranscript,
                ballotPayloads: thresholdOnlyFixture.ballotPayloads,
                ballotClosePayload: belowThresholdBallotClosePayload,
                decryptionSharePayloads:
                    thresholdOnlyFixture.decryptionSharePayloads,
                tallyPublications: thresholdOnlyFixture.tallyPublications,
            }),
        ).rejects.toThrow('Ballot close must include at least 5 participants');
    });

    it('rejects ballot close payloads that include a participant without a complete ballot', async () => {
        const incompleteBallotClosePayload = await signProtocolPayload(
            thresholdOnlyFixture.participants[0].auth.privateKey,
            {
                sessionId: thresholdOnlyFixture.sessionId,
                manifestHash: thresholdOnlyFixture.manifestHash,
                phase: 6,
                participantIndex: thresholdOnlyFixture.participants[0].index,
                messageType: 'ballot-close',
                includedParticipantIndices: [1, 2, 3, 4, 6],
            },
        );

        await expect(
            verifyElectionCeremonyDetailed({
                manifest: thresholdOnlyFixture.manifest,
                sessionId: thresholdOnlyFixture.sessionId,
                dkgTranscript: thresholdOnlyFixture.dkgTranscript,
                ballotPayloads: thresholdOnlyFixture.ballotPayloads,
                ballotClosePayload: incompleteBallotClosePayload,
                decryptionSharePayloads:
                    thresholdOnlyFixture.decryptionSharePayloads,
                tallyPublications: thresholdOnlyFixture.tallyPublications,
            }),
        ).rejects.toThrow(
            'Ballot close requires a complete ballot from participant 6',
        );
    });

    it('rejects decryption shares tied to a different counted ballot transcript', async () => {
        const forgedDecryptionSharePayload = await createDecryptionSharePayload(
            thresholdOnlyFixture.participants[0].auth.privateKey,
            {
                ...thresholdOnlyFixture.decryptionSharePayloads[0].payload,
                transcriptHash: 'aa'.repeat(32),
            },
        );

        await expect(
            verifyElectionCeremonyDetailed({
                manifest: thresholdOnlyFixture.manifest,
                sessionId: thresholdOnlyFixture.sessionId,
                dkgTranscript: thresholdOnlyFixture.dkgTranscript,
                ballotPayloads: thresholdOnlyFixture.ballotPayloads,
                ballotClosePayload: thresholdOnlyFixture.ballotClosePayload,
                decryptionSharePayloads: [
                    forgedDecryptionSharePayload,
                    ...thresholdOnlyFixture.decryptionSharePayloads.slice(1),
                ],
                tallyPublications: thresholdOnlyFixture.tallyPublications,
            }),
        ).rejects.toThrow(
            'Decryption share transcript hash mismatch for participant 1 and option 1',
        );
    });

    it('rejects tally publications that do not match the recomputed close-selected tally', async () => {
        const forgedTallyPublication = await createTallyPublicationPayload(
            thresholdOnlyFixture.participants[0].auth.privateKey,
            {
                ...thresholdOnlyFixture.tallyPublications[0].payload,
                tally: thresholdOnlyFixture.expectedTallies[0] + 1n,
            },
        );

        await expect(
            verifyElectionCeremonyDetailed({
                manifest: thresholdOnlyFixture.manifest,
                sessionId: thresholdOnlyFixture.sessionId,
                dkgTranscript: thresholdOnlyFixture.dkgTranscript,
                ballotPayloads: thresholdOnlyFixture.ballotPayloads,
                ballotClosePayload: thresholdOnlyFixture.ballotClosePayload,
                decryptionSharePayloads:
                    thresholdOnlyFixture.decryptionSharePayloads,
                tallyPublications: [
                    forgedTallyPublication,
                    ...thresholdOnlyFixture.tallyPublications.slice(1),
                ],
            }),
        ).rejects.toThrow(
            'Tally publication does not match the recomputed tally for option 1',
        );
    });
});
