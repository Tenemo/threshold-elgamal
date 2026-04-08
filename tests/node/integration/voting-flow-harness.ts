import {
    getGroup,
    modP,
    modPowP,
    modQ,
    sha256,
    utf8ToBytes,
    type CryptoGroup,
    type GroupName,
} from '#core';
import { replayGjkrTranscript, type DKGState } from '#dkg';
import { addEncryptedValues, encryptAdditiveWithRandomness } from '#elgamal';
import {
    createDLEQProof,
    createDisjunctiveProof,
    createSchnorrProof,
    verifyDLEQProof,
    verifyDisjunctiveProof,
    verifySchnorrProof,
    type DLEQStatement,
    type ProofContext,
} from '#proofs';
import {
    canonicalUnsignedPayloadBytes,
    canonicalizeJson,
    deriveSessionId,
    formatSessionFingerprint,
    hashElectionManifest,
    hashProtocolTranscript,
    type ComplaintPayload,
    type ElectionManifest,
    type EncryptedDualSharePayload,
    type FeldmanCommitmentPayload,
    type KeyDerivationConfirmation,
    type ManifestAcceptancePayload,
    type PedersenCommitmentPayload,
    type ProtocolPayload,
    type RegistrationPayload,
    type SignedPayload,
} from '#protocol';
import { bytesToHex, fixedHexToBigint } from '#serialize';
import {
    combineDecryptionShares,
    createVerifiedDecryptionShare,
    type DecryptionShare,
    type Share,
} from '#threshold';
import {
    decryptEnvelope,
    encryptEnvelope,
    exportAuthPublicKey,
    exportTransportPrivateKey,
    exportTransportPublicKey,
    generateAuthKeyPair,
    generateTransportKeyPair,
    resolveDealerChallenge,
    signPayloadBytes,
    verifyComplaintPrecondition,
    verifyPayloadSignature,
    type ComplaintResolution,
    type EncryptedEnvelope,
} from '#transport';
import {
    derivePedersenShares,
    generateFeldmanCommitments,
    generatePedersenCommitments,
    verifyFeldmanShare,
    verifyPedersenShare,
    type PedersenShare,
} from '#vss';

const DEFAULT_GROUP = 'ffdhe2048';

type ParticipantRuntime = {
    readonly auth: CryptoKeyPair;
    readonly authPublicKeyHex: string;
    readonly index: number;
    readonly transportPrivateKeyHex: string;
    readonly transportPublicKeyHex: string;
};

type EnvelopeArtifact = {
    readonly envelope: EncryptedEnvelope;
    readonly ephemeralPrivateKey: string;
    readonly recipientIndex: number;
    readonly share: PedersenShare;
    readonly signedPayload: SignedPayload<EncryptedDualSharePayload>;
};

type DealerMaterial = {
    readonly encryptedShares: readonly EnvelopeArtifact[];
    readonly feldmanCommitmentPayload: SignedPayload<FeldmanCommitmentPayload>;
    readonly feldmanCommitments: readonly bigint[];
    readonly participantIndex: number;
    readonly pedersenCommitmentPayload: SignedPayload<PedersenCommitmentPayload>;
    readonly pedersenShares: readonly PedersenShare[];
    readonly secretPolynomial: readonly bigint[];
};

export type ComplaintInjection = {
    readonly dealerIndex: number;
    readonly envelopeTamper: 'ciphertext' | 'ephemeralPublicKey' | 'iv';
    readonly reason?: ComplaintPayload['reason'];
    readonly recipientIndex: number;
};

export type VotingFlowScenario = {
    readonly allowAbstention?: boolean;
    readonly complaints?: readonly ComplaintInjection[];
    readonly decryptionParticipantIndices?: readonly number[];
    readonly group?: GroupName;
    readonly participantCount: number;
    readonly threshold: number;
    readonly votes: readonly bigint[];
};

type CommonScenarioResult = {
    readonly aggregate: { readonly c1: bigint; readonly c2: bigint };
    readonly ballotLogHash?: string;
    readonly ballots: readonly {
        readonly ciphertext: { readonly c1: bigint; readonly c2: bigint };
        readonly proof: Awaited<ReturnType<typeof createDisjunctiveProof>>;
        readonly proofContext: ProofContext;
        readonly vote: bigint;
        readonly voterIndex: number;
    }[];
    readonly complaintResolutions: readonly (ComplaintResolution & {
        readonly dealerIndex: number;
        readonly recipientIndex: number;
    })[];
    readonly directJointSecret?: bigint;
    readonly finalShares?: readonly Share[];
    readonly finalState: DKGState;
    readonly group: CryptoGroup;
    readonly jointPublicKey?: bigint;
    readonly manifestHash: string;
    readonly mismatchedAggregate?: {
        readonly c1: bigint;
        readonly c2: bigint;
    };
    readonly registrations: readonly SignedPayload<RegistrationPayload>[];
    readonly sessionFingerprint: string;
    readonly sessionId: string;
    readonly thresholdShareArtifacts?: readonly {
        readonly proof: Awaited<ReturnType<typeof createDLEQProof>>;
        readonly share: DecryptionShare;
    }[];
    readonly transcriptDerivedVerificationKeys?: readonly {
        readonly index: number;
        readonly value: bigint;
    }[];
};

export type CompletedVotingFlowResult = CommonScenarioResult & {
    readonly expectedTally: bigint;
    readonly finalState: DKGState & { readonly phase: 'completed' };
    readonly recovered: bigint;
    readonly recoveredWithAllShares: bigint;
};

export type AbortedVotingFlowResult = CommonScenarioResult & {
    readonly finalState: DKGState & { readonly phase: 'aborted' };
};

export type VotingFlowResult =
    | CompletedVotingFlowResult
    | AbortedVotingFlowResult;

const validScoresWithoutAbstention: readonly bigint[] = [
    1n,
    2n,
    3n,
    4n,
    5n,
    6n,
    7n,
    8n,
    9n,
    10n,
] as const;

const validScoresWithAbstention: readonly bigint[] = [
    0n,
    ...validScoresWithoutAbstention,
] as const;

const invariant: (condition: boolean, message: string) => asserts condition = (
    condition,
    message,
) => {
    if (!condition) {
        throw new Error(message);
    }
};

const createDeterministicSource = (seed: number) => {
    let counter = seed & 0xff;

    return (length: number): Uint8Array => {
        const bytes = new Uint8Array(length);
        for (let index = 0; index < length; index += 1) {
            bytes[index] = (counter + index) & 0xff;
        }
        counter = (counter + length + 17) & 0xff;
        return bytes;
    };
};

const hashCanonicalJson = async (
    value: unknown,
    bigintByteLength?: number,
): Promise<string> =>
    bytesToHex(
        await sha256(
            utf8ToBytes(
                canonicalizeJson(value as never, {
                    bigintByteLength,
                }),
            ),
        ),
    );

const signPayload = async <TPayload extends ProtocolPayload>(
    privateKey: CryptoKey,
    payload: TPayload,
): Promise<SignedPayload<TPayload>> => ({
    payload,
    signature: await signPayloadBytes(
        privateKey,
        canonicalUnsignedPayloadBytes(payload),
    ),
});

const verifySignedTranscript = async (
    participants: readonly ParticipantRuntime[],
    signedPayloads: readonly SignedPayload[],
): Promise<void> => {
    const participantMap = new Map(
        participants.map((participant) => [participant.index, participant]),
    );

    const verifications = await Promise.all(
        signedPayloads.map(async (signedPayload) => {
            const participant = participantMap.get(
                signedPayload.payload.participantIndex,
            );
            invariant(
                participant !== undefined,
                `Missing participant ${signedPayload.payload.participantIndex} for signature verification`,
            );

            return verifyPayloadSignature(
                participant.auth.publicKey,
                canonicalUnsignedPayloadBytes(signedPayload.payload),
                signedPayload.signature,
            );
        }),
    );

    invariant(
        verifications.every(Boolean),
        'One or more signed protocol payloads failed verification',
    );
};

const computeRosterHash = async (
    participants: readonly ParticipantRuntime[],
): Promise<string> =>
    hashCanonicalJson(
        participants.map((participant) => ({
            participantIndex: participant.index,
            authPublicKey: participant.authPublicKeyHex,
            transportPublicKey: participant.transportPublicKeyHex,
        })),
    );

const parseShareEnvelope = (
    plaintext: Uint8Array,
    expectedIndex: number,
): PedersenShare => {
    const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as {
        readonly blindingValue: string;
        readonly index: number;
        readonly secretValue: string;
    };

    invariant(
        parsed.index === expectedIndex,
        `Expected share envelope for participant ${expectedIndex}, received ${parsed.index}`,
    );

    return {
        index: parsed.index,
        secretValue: fixedHexToBigint(parsed.secretValue),
        blindingValue: fixedHexToBigint(parsed.blindingValue),
    };
};

const deriveVerificationKeyFromCommitments = (
    commitmentSets: readonly (readonly bigint[])[],
    participantIndex: number,
    group: CryptoGroup,
): bigint => {
    const point = BigInt(participantIndex);

    return commitmentSets.reduce((outerAccumulator, commitments) => {
        let innerAccumulator = 1n;
        let exponent = 1n;

        for (const commitment of commitments) {
            innerAccumulator = modP(
                innerAccumulator * modPowP(commitment, exponent, group.p),
                group.p,
            );
            exponent = modQ(exponent * point, group.q);
        }

        return modP(outerAccumulator * innerAccumulator, group.p);
    }, 1n);
};

const createParticipants = async (
    participantCount: number,
): Promise<readonly ParticipantRuntime[]> =>
    Promise.all(
        Array.from({ length: participantCount }, async (_value, offset) => {
            const index = offset + 1;
            const auth = await generateAuthKeyPair();
            const transport = await generateTransportKeyPair('P-256');

            return {
                index,
                auth,
                authPublicKeyHex: await exportAuthPublicKey(auth.publicKey),
                transportPublicKeyHex: await exportTransportPublicKey(
                    transport.publicKey,
                ),
                transportPrivateKeyHex: await exportTransportPrivateKey(
                    transport.privateKey,
                ),
            };
        }),
    );

const buildManifest = (
    rosterHash: string,
    group: CryptoGroup,
    scenario: VotingFlowScenario,
): ElectionManifest => ({
    protocolVersion: 'v2',
    suiteId: group.name,
    threshold: scenario.threshold,
    participantCount: scenario.participantCount,
    minimumPublicationThreshold: scenario.participantCount,
    allowAbstention: scenario.allowAbstention ?? false,
    scoreDomainMin: scenario.allowAbstention ? 0 : 1,
    scoreDomainMax: 10,
    ballotFinality: 'first-valid',
    rosterHash,
    optionList: ['Option A'],
    epochDeadlines: ['2026-04-08T12:00:00Z'],
});

const createRegistrationPayloads = async (
    participants: readonly ParticipantRuntime[],
    sessionId: string,
    manifestHash: string,
    rosterHash: string,
): Promise<readonly SignedPayload<RegistrationPayload>[]> =>
    Promise.all(
        participants.map((participant) =>
            signPayload(participant.auth.privateKey, {
                sessionId,
                manifestHash,
                phase: 0,
                participantIndex: participant.index,
                messageType: 'registration',
                rosterHash,
                authPublicKey: participant.authPublicKeyHex,
                transportPublicKey: participant.transportPublicKeyHex,
            }),
        ),
    );

const createAcceptancePayloads = async (
    participants: readonly ParticipantRuntime[],
    sessionId: string,
    manifestHash: string,
    rosterHash: string,
): Promise<readonly SignedPayload<ManifestAcceptancePayload>[]> =>
    Promise.all(
        participants.map((participant) =>
            signPayload(participant.auth.privateKey, {
                sessionId,
                manifestHash,
                phase: 0,
                participantIndex: participant.index,
                messageType: 'manifest-acceptance',
                rosterHash,
                assignedParticipantIndex: participant.index,
            }),
        ),
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

const buildDealerMaterial = async (
    participant: ParticipantRuntime,
    participants: readonly ParticipantRuntime[],
    sessionId: string,
    manifestHash: string,
    rosterHash: string,
    group: CryptoGroup,
    threshold: number,
): Promise<DealerMaterial> => {
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
    const pedersenShares = derivePedersenShares(
        secretPolynomial,
        blindingPolynomial,
        participants.length,
        group.q,
    );
    const feldmanCommitments = generateFeldmanCommitments(
        secretPolynomial,
        group,
    );

    const schnorrProofs = await Promise.all(
        secretPolynomial.map(async (coefficient, coefficientIndex) => {
            const proofCoefficientIndex = coefficientIndex + 1;
            const context: ProofContext = {
                protocolVersion: 'v2',
                suiteId: group.name,
                manifestHash,
                sessionId,
                label: 'feldman-coefficient-proof',
                participantIndex: participant.index,
                coefficientIndex: proofCoefficientIndex,
            };
            const proof = await createSchnorrProof(
                coefficient,
                feldmanCommitments.commitments[coefficientIndex],
                group,
                context,
                createDeterministicSource(
                    participant.index * 29 + coefficientIndex,
                ),
            );

            invariant(
                await verifySchnorrProof(
                    proof,
                    feldmanCommitments.commitments[coefficientIndex],
                    group,
                    context,
                ),
                `Invalid Feldman Schnorr proof for dealer ${participant.index}`,
            );

            return {
                coefficientIndex: proofCoefficientIndex,
                challenge: proof.challenge,
                response: proof.response,
            };
        }),
    );

    for (const share of pedersenShares) {
        invariant(
            verifyPedersenShare(share, pedersenCommitments, group),
            `Invalid Pedersen share for dealer ${participant.index} and recipient ${share.index}`,
        );
        invariant(
            verifyFeldmanShare(
                { index: share.index, value: share.secretValue },
                feldmanCommitments,
                group,
            ),
            `Invalid Feldman share for dealer ${participant.index} and recipient ${share.index}`,
        );
    }

    const encryptedShares = await Promise.all(
        participants
            .filter((recipient) => recipient.index !== participant.index)
            .map(async (recipient) => {
                const share = pedersenShares[recipient.index - 1];
                const plaintext = utf8ToBytes(
                    canonicalizeJson(
                        {
                            index: recipient.index,
                            secretValue: share.secretValue,
                            blindingValue: share.blindingValue,
                        },
                        {
                            bigintByteLength: group.byteLength,
                        },
                    ),
                );
                const { envelope, ephemeralPrivateKey } = await encryptEnvelope(
                    plaintext,
                    recipient.transportPublicKeyHex,
                    {
                        sessionId,
                        rosterHash,
                        phase: 1,
                        dealerIndex: participant.index,
                        recipientIndex: recipient.index,
                        envelopeId: `env-${participant.index}-${recipient.index}`,
                        payloadType: 'encrypted-dual-share',
                        protocolVersion: 'v2',
                        suite: 'P-256',
                    },
                );
                const decrypted = await decryptEnvelope(
                    envelope,
                    recipient.transportPrivateKeyHex,
                );
                const decodedShare = parseShareEnvelope(
                    decrypted,
                    recipient.index,
                );

                invariant(
                    decodedShare.index === share.index &&
                        decodedShare.secretValue === share.secretValue &&
                        decodedShare.blindingValue === share.blindingValue,
                    `Envelope round-trip mismatch for dealer ${participant.index} to recipient ${recipient.index}`,
                );
                invariant(
                    await verifyComplaintPrecondition(
                        recipient.transportPrivateKeyHex,
                        recipient.transportPublicKeyHex,
                        'P-256',
                    ),
                    `Complaint precondition failed for participant ${recipient.index}`,
                );

                return {
                    recipientIndex: recipient.index,
                    share,
                    envelope,
                    ephemeralPrivateKey,
                    signedPayload: await signPayload(
                        participant.auth.privateKey,
                        {
                            sessionId,
                            manifestHash,
                            phase: 1,
                            participantIndex: participant.index,
                            messageType: 'encrypted-dual-share',
                            recipientIndex: recipient.index,
                            envelopeId: envelope.envelopeId,
                            suite: envelope.suite,
                            ephemeralPublicKey: envelope.ephemeralPublicKey,
                            iv: envelope.iv,
                            ciphertext: envelope.ciphertext,
                        },
                    ),
                } satisfies EnvelopeArtifact;
            }),
    );

    return {
        participantIndex: participant.index,
        secretPolynomial,
        pedersenShares,
        pedersenCommitmentPayload: await signPayload(
            participant.auth.privateKey,
            {
                sessionId,
                manifestHash,
                phase: 1,
                participantIndex: participant.index,
                messageType: 'pedersen-commitment',
                commitments: pedersenCommitments.commitments.map((value) =>
                    value.toString(16),
                ),
            },
        ),
        feldmanCommitments: feldmanCommitments.commitments,
        feldmanCommitmentPayload: await signPayload(
            participant.auth.privateKey,
            {
                sessionId,
                manifestHash,
                phase: 3,
                participantIndex: participant.index,
                messageType: 'feldman-commitment',
                commitments: feldmanCommitments.commitments.map((value) =>
                    value.toString(16),
                ),
                proofs: schnorrProofs.map((proof) => ({
                    coefficientIndex: proof.coefficientIndex,
                    challenge: proof.challenge.toString(16),
                    response: proof.response.toString(16),
                })),
            },
        ),
        encryptedShares,
    };
};

const mutateHexTail = (value: string): string => {
    invariant(
        value.length >= 2,
        'Expected at least one byte of hexadecimal data',
    );
    const tail = value.slice(-2).toLowerCase();
    const replacement = tail === '00' ? 'ff' : '00';
    return `${value.slice(0, -2)}${replacement}`;
};

const tamperEnvelope = (
    envelope: EncryptedEnvelope,
    tamper: ComplaintInjection['envelopeTamper'],
): EncryptedEnvelope => {
    switch (tamper) {
        case 'ciphertext':
            return {
                ...envelope,
                ciphertext: mutateHexTail(envelope.ciphertext),
            };
        case 'iv':
            return { ...envelope, iv: mutateHexTail(envelope.iv) };
        case 'ephemeralPublicKey':
            return {
                ...envelope,
                ephemeralPublicKey: mutateHexTail(envelope.ephemeralPublicKey),
            };
    }
};

const createBallotArtifacts = async (
    votes: readonly bigint[],
    jointPublicKey: bigint,
    group: CryptoGroup,
    manifestHash: string,
    sessionId: string,
    validValues: readonly bigint[],
): Promise<
    readonly {
        readonly ciphertext: { readonly c1: bigint; readonly c2: bigint };
        readonly proof: Awaited<ReturnType<typeof createDisjunctiveProof>>;
        readonly proofContext: ProofContext;
        readonly vote: bigint;
        readonly voterIndex: number;
    }[]
> =>
    Promise.all(
        votes.map(async (vote, offset) => {
            const voterIndex = offset + 1;
            const randomness = BigInt(101 + offset * 103);
            const ciphertext = encryptAdditiveWithRandomness(
                vote,
                jointPublicKey,
                randomness,
                10n,
                group.name,
            );
            const proofContext: ProofContext = {
                protocolVersion: 'v2',
                suiteId: group.name,
                manifestHash,
                sessionId,
                label: 'ballot-range-proof',
                voterIndex,
                optionIndex: 1,
            };
            const proof = await createDisjunctiveProof(
                vote,
                randomness,
                ciphertext,
                jointPublicKey,
                validValues,
                group,
                proofContext,
                createDeterministicSource(voterIndex * 31),
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
        scenario.threshold >= 1 &&
            scenario.threshold <= scenario.participantCount,
        'Scenario threshold must satisfy 1 <= k <= n',
    );
    invariant(
        scenario.votes.length === scenario.participantCount,
        'Scenario votes must match the participant count',
    );

    const validValues: readonly bigint[] = scenario.allowAbstention
        ? validScoresWithAbstention
        : validScoresWithoutAbstention;

    scenario.votes.forEach((vote, index) => {
        invariant(
            validValues.includes(vote),
            `Vote ${vote.toString()} for participant ${index + 1} is outside the allowed domain`,
        );
        invariant(
            vote <= 10n,
            'Vote exceeds the supported single-ballot bound',
        );
    });

    const group = getGroup(scenario.group ?? DEFAULT_GROUP);
    const participants = await createParticipants(scenario.participantCount);
    const rosterHash = await computeRosterHash(participants);
    const manifest = buildManifest(rosterHash, group, scenario);
    const manifestHash = await hashElectionManifest(manifest);
    const sessionId = await deriveSessionId(
        manifestHash,
        rosterHash,
        `nonce-${scenario.participantCount}-${scenario.threshold}-${scenario.votes.join('-')}`,
        `2026-04-08T12:${String(scenario.participantCount).padStart(2, '0')}:00Z`,
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
        ...registrations,
        ...acceptances,
    ]);

    const setupTranscriptHash = await hashProtocolTranscript(
        [...registrations, ...acceptances].map((item) => item.payload),
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
                scenario.threshold,
            ),
        ),
    );

    const complaintResolutions: (ComplaintResolution & {
        readonly dealerIndex: number;
        readonly recipientIndex: number;
    })[] = [];
    const complaintPayloads: SignedPayload<ComplaintPayload>[] = [];
    const complainedDealerIndices = new Set<number>();
    const tamperedEnvelopePayloads = new Map<
        string,
        SignedPayload<EncryptedDualSharePayload>
    >();

    for (const complaint of scenario.complaints ?? []) {
        const dealerMaterial = dealerMaterials.find(
            (dealer) => dealer.participantIndex === complaint.dealerIndex,
        );
        const recipient = participants.find(
            (participant) => participant.index === complaint.recipientIndex,
        );

        invariant(
            dealerMaterial !== undefined,
            `Unknown complaint dealer ${complaint.dealerIndex}`,
        );
        invariant(
            recipient !== undefined,
            `Unknown complaint recipient ${complaint.recipientIndex}`,
        );

        const envelopeArtifact = dealerMaterial.encryptedShares.find(
            (item) => item.recipientIndex === complaint.recipientIndex,
        );
        invariant(
            envelopeArtifact !== undefined,
            `Dealer ${complaint.dealerIndex} did not produce an envelope for recipient ${complaint.recipientIndex}`,
        );
        invariant(
            await verifyComplaintPrecondition(
                recipient.transportPrivateKeyHex,
                recipient.transportPublicKeyHex,
                'P-256',
            ),
            `Complaint precondition failed for participant ${complaint.recipientIndex}`,
        );

        const tamperedEnvelope = tamperEnvelope(
            envelopeArtifact.envelope,
            complaint.envelopeTamper,
        );

        await decryptEnvelope(
            tamperedEnvelope,
            recipient.transportPrivateKeyHex,
        ).then(
            () => {
                throw new Error(
                    `Tampered envelope unexpectedly decrypted for dealer ${complaint.dealerIndex}`,
                );
            },
            () => undefined,
        );

        const resolution = await resolveDealerChallenge(
            tamperedEnvelope,
            recipient.transportPrivateKeyHex,
            envelopeArtifact.ephemeralPrivateKey,
        );
        complaintResolutions.push({
            ...resolution,
            dealerIndex: complaint.dealerIndex,
            recipientIndex: complaint.recipientIndex,
        });
        invariant(
            resolution.valid === false && resolution.fault === 'dealer',
            `Expected dealer fault for complaint against dealer ${complaint.dealerIndex}`,
        );

        complainedDealerIndices.add(complaint.dealerIndex);
        tamperedEnvelopePayloads.set(
            `${complaint.dealerIndex}:${complaint.recipientIndex}`,
            await signPayload(
                participants[complaint.dealerIndex - 1].auth.privateKey,
                {
                    sessionId,
                    manifestHash,
                    phase: 1,
                    participantIndex: complaint.dealerIndex,
                    messageType: 'encrypted-dual-share',
                    recipientIndex: complaint.recipientIndex,
                    envelopeId: tamperedEnvelope.envelopeId,
                    suite: tamperedEnvelope.suite,
                    ephemeralPublicKey: tamperedEnvelope.ephemeralPublicKey,
                    iv: tamperedEnvelope.iv,
                    ciphertext: tamperedEnvelope.ciphertext,
                },
            ),
        );
        complaintPayloads.push(
            await signPayload(recipient.auth.privateKey, {
                sessionId,
                manifestHash,
                phase: 2,
                participantIndex: recipient.index,
                messageType: 'complaint',
                dealerIndex: complaint.dealerIndex,
                envelopeId: tamperedEnvelope.envelopeId,
                reason: complaint.reason ?? 'aes-gcm-failure',
            }),
        );
    }

    const allEncryptedSharePayloads = dealerMaterials.flatMap((dealer) =>
        dealer.encryptedShares.map((item) => {
            const tampered = tamperedEnvelopePayloads.get(
                `${dealer.participantIndex}:${item.recipientIndex}`,
            );
            return tampered ?? item.signedPayload;
        }),
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
        ...registrations,
        ...acceptances,
        ...dealerMaterials.map((dealer) => dealer.pedersenCommitmentPayload),
        ...allEncryptedSharePayloads,
        ...complaintPayloads,
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
                publicKey: 'pending',
            } satisfies KeyDerivationConfirmation),
        ),
    );

    const dkgTranscript = [
        ...registrations,
        ...acceptances,
        ...dealerMaterials.map((dealer) => dealer.pedersenCommitmentPayload),
        ...allEncryptedSharePayloads,
        ...complaintPayloads,
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
            threshold: scenario.threshold,
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
            finalState: abortedState,
            group,
            manifestHash,
            registrations,
            sessionFingerprint,
            sessionId,
        };
    }

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
    const jointPublicKey = qualDealerMaterials.reduce(
        (accumulator, dealer) =>
            modP(accumulator * dealer.feldmanCommitments[0], group.p),
        1n,
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

    const transcriptDerivedVerificationKeys = finalShares.map((share) => {
        const transcriptKey = deriveVerificationKeyFromCommitments(
            qualDealerMaterials.map((dealer) => dealer.feldmanCommitments),
            share.index,
            group,
        );

        invariant(
            transcriptKey === modPowP(group.g, share.value, group.p),
            `Transcript-derived verification key mismatch for participant ${share.index}`,
        );

        return {
            index: share.index,
            value: transcriptKey,
        };
    });

    const ballots = await createBallotArtifacts(
        scenario.votes,
        jointPublicKey,
        group,
        manifestHash,
        sessionId,
        validValues,
    );
    const aggregate = ballots
        .map((ballot) => ballot.ciphertext)
        .reduce(
            (accumulator, ciphertext) =>
                addEncryptedValues(accumulator, ciphertext, group.name),
            { c1: 1n, c2: 1n },
        );
    const reverseAggregate = [...ballots]
        .reverse()
        .map((ballot) => ballot.ciphertext)
        .reduce(
            (accumulator, ciphertext) =>
                addEncryptedValues(accumulator, ciphertext, group.name),
            { c1: 1n, c2: 1n },
        );

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

    const ballotLogHash = await hashCanonicalJson(
        ballots.map((ballot) => ({
            voterIndex: ballot.voterIndex,
            optionIndex: ballot.proofContext.optionIndex,
            ciphertext: ballot.ciphertext,
            proof: ballot.proof,
        })),
        group.byteLength,
    );
    const verifiedAggregate = {
        transcriptHash: ballotLogHash,
        ciphertext: aggregate,
    } as const;

    const selectedIndices =
        scenario.decryptionParticipantIndices ??
        qual.slice(0, scenario.threshold);

    invariant(
        selectedIndices.length >= scenario.threshold,
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

    const thresholdShareArtifacts = await Promise.all(
        selectedShares.map(async (share) => {
            const decryptionShare = createVerifiedDecryptionShare(
                verifiedAggregate,
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
                ciphertext: aggregate,
                decryptionShare: decryptionShare.value,
            };
            const proofContext: ProofContext = {
                protocolVersion: 'v2',
                suiteId: group.name,
                manifestHash,
                sessionId,
                label: 'decryption-share-dleq',
                participantIndex: share.index,
            };
            const proof = await createDLEQProof(
                share.value,
                statement,
                group,
                proofContext,
                createDeterministicSource(200 + share.index),
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

    const recovered = combineDecryptionShares(
        aggregate,
        thresholdShareArtifacts.map((item) => item.share),
        group,
        BigInt(scenario.participantCount * 10),
    );
    const recoveredWithAllShares = combineDecryptionShares(
        aggregate,
        finalShares.map((share) =>
            createVerifiedDecryptionShare(verifiedAggregate, share, group),
        ),
        group,
        BigInt(scenario.participantCount * 10),
    );
    const expectedTally = scenario.votes.reduce((sum, vote) => sum + vote, 0n);

    invariant(
        recovered === expectedTally,
        'Threshold subset recovered the wrong tally',
    );
    invariant(
        recoveredWithAllShares === expectedTally,
        'All-share threshold recovery returned the wrong tally',
    );

    return {
        aggregate,
        ballotLogHash,
        ballots,
        complaintResolutions,
        directJointSecret,
        expectedTally,
        finalShares,
        finalState: completedState,
        group,
        jointPublicKey,
        manifestHash,
        mismatchedAggregate,
        recovered,
        recoveredWithAllShares,
        registrations,
        sessionFingerprint,
        sessionId,
        thresholdShareArtifacts,
        transcriptDerivedVerificationKeys,
    };
};
