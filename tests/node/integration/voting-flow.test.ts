import { describe, expect, it } from 'vitest';

import {
    getGroup,
    modP,
    modPowP,
    modQ,
    sha256,
    utf8ToBytes,
    type CryptoGroup,
} from '#core';
import { replayGjkrTranscript } from '#dkg';
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
} from '#transport';
import {
    derivePedersenShares,
    generateFeldmanCommitments,
    generatePedersenCommitments,
    verifyFeldmanShare,
    verifyPedersenShare,
    type PedersenShare,
} from '#vss';

type ParticipantRuntime = {
    readonly auth: CryptoKeyPair;
    readonly authPublicKeyHex: string;
    readonly index: number;
    readonly transportPrivateKeyHex: string;
    readonly transportPublicKeyHex: string;
};

type DealerMaterial = {
    readonly encryptedSharePayloads: readonly SignedPayload<EncryptedDualSharePayload>[];
    readonly feldmanCommitmentPayload: SignedPayload<FeldmanCommitmentPayload>;
    readonly feldmanCommitments: readonly bigint[];
    readonly pedersenCommitmentPayload: SignedPayload<PedersenCommitmentPayload>;
    readonly pedersenShares: readonly PedersenShare[];
    readonly secretPolynomial: readonly bigint[];
};

const validScores = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n, 9n, 10n] as const;

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

const verifySignedPayload = async (
    participant: ParticipantRuntime,
    signedPayload: SignedPayload,
): Promise<boolean> =>
    verifyPayloadSignature(
        participant.auth.publicKey,
        canonicalUnsignedPayloadBytes(signedPayload.payload),
        signedPayload.signature,
    );

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

    expect(parsed.index).toBe(expectedIndex);

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

const createParticipants = async (): Promise<readonly ParticipantRuntime[]> =>
    Promise.all(
        [1, 2, 3].map(async (index) => {
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
): ElectionManifest => ({
    protocolVersion: 'v2',
    suiteId: group.name,
    threshold: 2,
    participantCount: 3,
    minimumPublicationThreshold: 3,
    allowAbstention: false,
    scoreDomainMin: 1,
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

const buildDealerMaterial = async (
    participant: ParticipantRuntime,
    participants: readonly ParticipantRuntime[],
    sessionId: string,
    manifestHash: string,
    rosterHash: string,
    group: CryptoGroup,
    secretPolynomial: readonly bigint[],
    blindingPolynomial: readonly bigint[],
): Promise<DealerMaterial> => {
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
                label: 'phase3-feldman',
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

            await expect(
                verifySchnorrProof(
                    proof,
                    feldmanCommitments.commitments[coefficientIndex],
                    group,
                    context,
                ),
            ).resolves.toBe(true);

            return {
                coefficientIndex: proofCoefficientIndex,
                challenge: proof.challenge,
                response: proof.response,
            };
        }),
    );

    pedersenShares.forEach((share) => {
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

    const encryptedSharePayloads = await Promise.all(
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
                const { envelope } = await encryptEnvelope(
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

                expect(parseShareEnvelope(decrypted, recipient.index)).toEqual(
                    share,
                );
                await expect(
                    verifyComplaintPrecondition(
                        recipient.transportPrivateKeyHex,
                        recipient.transportPublicKeyHex,
                        'P-256',
                    ),
                ).resolves.toBe(true);

                return signPayload(participant.auth.privateKey, {
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
                });
            }),
    );

    return {
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
        encryptedSharePayloads,
    };
};

describe('three-participant end-to-end flows', () => {
    it('runs a complaint-free 2-of-3 voting flow from signed setup through DLEQ-backed tally decryption', async () => {
        const group = getGroup('ffdhe2048');
        const participants = await createParticipants();
        const rosterHash = await computeRosterHash(participants);
        const manifest = buildManifest(rosterHash, group);
        const manifestHash = await hashElectionManifest(manifest);
        const sessionId = await deriveSessionId(
            manifestHash,
            rosterHash,
            'nonce-three-participants',
            '2026-04-08T12:00:00Z',
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

        for (const signedPayload of [...registrations, ...acceptances]) {
            const participant = participants.find(
                (item) => item.index === signedPayload.payload.participantIndex,
            );

            expect(participant).toBeDefined();
            await expect(
                verifySignedPayload(participant!, signedPayload),
            ).resolves.toBe(true);
        }

        const setupTranscriptHash = await hashProtocolTranscript(
            [...registrations, ...acceptances].map((item) => item.payload),
        );
        expect(formatSessionFingerprint(setupTranscriptHash)).toMatch(
            /^[0-9A-F]{4}(?:-[0-9A-F]{4}){7}$/,
        );

        const dealerMaterials = await Promise.all([
            buildDealerMaterial(
                participants[0],
                participants,
                sessionId,
                manifestHash,
                rosterHash,
                group,
                [5n, 2n],
                [11n, 7n],
            ),
            buildDealerMaterial(
                participants[1],
                participants,
                sessionId,
                manifestHash,
                rosterHash,
                group,
                [13n, 3n],
                [17n, 5n],
            ),
            buildDealerMaterial(
                participants[2],
                participants,
                sessionId,
                manifestHash,
                rosterHash,
                group,
                [19n, 4n],
                [23n, 6n],
            ),
        ]);

        const finalShares: readonly Share[] = participants.map(
            (participant) => ({
                index: participant.index,
                value: modQ(
                    dealerMaterials.reduce(
                        (sum, dealer) =>
                            sum +
                            dealer.pedersenShares[participant.index - 1]
                                .secretValue,
                        0n,
                    ),
                    group.q,
                ),
            }),
        );
        const jointPublicKey = dealerMaterials.reduce(
            (accumulator, dealer) =>
                modP(accumulator * dealer.feldmanCommitments[0], group.p),
            1n,
        );
        const directJointSecret = modQ(
            dealerMaterials.reduce(
                (sum, dealer) => sum + dealer.secretPolynomial[0],
                0n,
            ),
            group.q,
        );

        expect(jointPublicKey).toBe(
            modPowP(group.g, directJointSecret, group.p),
        );

        const transcriptDerivedVerificationKeys = finalShares.map((share) => {
            const transcriptKey = deriveVerificationKeyFromCommitments(
                dealerMaterials.map((dealer) => dealer.feldmanCommitments),
                share.index,
                group,
            );

            expect(transcriptKey).toBe(modPowP(group.g, share.value, group.p));

            return {
                index: share.index,
                value: transcriptKey,
            };
        });

        const preConfirmationQualHash = await hashProtocolTranscript(
            [
                ...registrations,
                ...acceptances,
                ...dealerMaterials.map(
                    (dealer) => dealer.pedersenCommitmentPayload,
                ),
                ...dealerMaterials.flatMap(
                    (dealer) => dealer.encryptedSharePayloads,
                ),
                ...dealerMaterials.map(
                    (dealer) => dealer.feldmanCommitmentPayload,
                ),
            ].map((item) => item.payload),
        );

        const confirmations = await Promise.all(
            participants.map((participant) =>
                signPayload(participant.auth.privateKey, {
                    sessionId,
                    manifestHash,
                    phase: 4,
                    participantIndex: participant.index,
                    messageType: 'key-derivation-confirmation',
                    qualHash: preConfirmationQualHash,
                    publicKey: jointPublicKey.toString(16),
                } satisfies KeyDerivationConfirmation),
            ),
        );

        const gjkrTranscript = [
            ...registrations,
            ...acceptances,
            ...dealerMaterials.map(
                (dealer) => dealer.pedersenCommitmentPayload,
            ),
            ...dealerMaterials.flatMap(
                (dealer) => dealer.encryptedSharePayloads,
            ),
            ...dealerMaterials.map((dealer) => dealer.feldmanCommitmentPayload),
            ...confirmations,
        ] as const;
        const finalState = replayGjkrTranscript(
            {
                protocol: 'gjkr',
                sessionId,
                manifestHash,
                group: group.name,
                participantCount: 3,
                threshold: 2,
            },
            gjkrTranscript,
        );

        expect(finalState.phase).toBe('completed');
        expect(finalState.qual).toEqual([1, 2, 3]);
        expect(finalState.manifestAccepted).toEqual([1, 2, 3]);

        const ballots = await Promise.all(
            [7n, 4n, 9n].map(async (vote, offset) => {
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
                    label: 'ballot-range',
                    voterIndex,
                    optionIndex: 1,
                };
                const proof = await createDisjunctiveProof(
                    vote,
                    randomness,
                    ciphertext,
                    jointPublicKey,
                    validScores,
                    group,
                    proofContext,
                    createDeterministicSource(voterIndex * 31),
                );

                await expect(
                    verifyDisjunctiveProof(
                        proof,
                        ciphertext,
                        jointPublicKey,
                        validScores,
                        group,
                        proofContext,
                    ),
                ).resolves.toBe(true);

                return {
                    voterIndex,
                    vote,
                    ciphertext,
                    proof,
                    proofContext,
                };
            }),
        );

        await expect(
            verifyDisjunctiveProof(
                ballots[0].proof,
                ballots[0].ciphertext,
                jointPublicKey,
                validScores,
                group,
                { ...ballots[0].proofContext, voterIndex: 99 },
            ),
        ).resolves.toBe(false);

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

        expect(reverseAggregate).toEqual(aggregate);

        const incompleteAggregate = ballots
            .slice(0, 2)
            .map((ballot) => ballot.ciphertext)
            .reduce(
                (accumulator, ciphertext) =>
                    addEncryptedValues(accumulator, ciphertext, group.name),
                { c1: 1n, c2: 1n },
            );
        expect(incompleteAggregate).not.toEqual(aggregate);

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

        const decryptionArtifacts = await Promise.all(
            [finalShares[0], finalShares[2]].map(async (share) => {
                const decryptionShare = createVerifiedDecryptionShare(
                    verifiedAggregate,
                    share,
                    group,
                );
                const statement: DLEQStatement = {
                    publicKey: transcriptDerivedVerificationKeys.find(
                        (item) => item.index === share.index,
                    )!.value,
                    ciphertext: aggregate,
                    decryptionShare: decryptionShare.value,
                };
                const proofContext: ProofContext = {
                    protocolVersion: 'v2',
                    suiteId: group.name,
                    manifestHash,
                    sessionId,
                    label: 'decryption-dleq',
                    participantIndex: share.index,
                };
                const proof = await createDLEQProof(
                    share.value,
                    statement,
                    group,
                    proofContext,
                    createDeterministicSource(200 + share.index),
                );

                await expect(
                    verifyDLEQProof(proof, statement, group, proofContext),
                ).resolves.toBe(true);

                return {
                    proof,
                    share: decryptionShare,
                };
            }),
        );

        const recovered = combineDecryptionShares(
            aggregate,
            decryptionArtifacts.map((item) => item.share),
            group,
            30n,
        );
        const recoveredWithAllShares = combineDecryptionShares(
            aggregate,
            finalShares.map((share) =>
                createVerifiedDecryptionShare(verifiedAggregate, share, group),
            ),
            group,
            30n,
        );

        expect(recovered).toBe(20n);
        expect(recoveredWithAllShares).toBe(20n);
    });

    it('resolves an AES-GCM complaint against the dealer and aborts a 3-of-3 ceremony when QUAL becomes too small', async () => {
        const group = getGroup('ffdhe2048');
        const participants = await createParticipants();
        const rosterHash = await computeRosterHash(participants);
        const manifest = {
            ...buildManifest(rosterHash, group),
            threshold: 3,
        } satisfies ElectionManifest;
        const manifestHash = await hashElectionManifest(manifest);
        const sessionId = await deriveSessionId(
            manifestHash,
            rosterHash,
            'nonce-complaint',
            '2026-04-08T13:00:00Z',
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
        const pedersenPayloads = await Promise.all(
            participants.map((participant) =>
                signPayload(participant.auth.privateKey, {
                    sessionId,
                    manifestHash,
                    phase: 1,
                    participantIndex: participant.index,
                    messageType: 'pedersen-commitment',
                    commitments: [`dealer-${participant.index}`],
                } satisfies PedersenCommitmentPayload),
            ),
        );

        const dealer = participants[0];
        const recipient = participants[1];
        const { envelope, ephemeralPrivateKey } = await encryptEnvelope(
            utf8ToBytes('share-pair'),
            recipient.transportPublicKeyHex,
            {
                sessionId,
                rosterHash,
                phase: 1,
                dealerIndex: dealer.index,
                recipientIndex: recipient.index,
                envelopeId: 'env-malformed',
                payloadType: 'encrypted-dual-share',
                protocolVersion: 'v2',
                suite: 'P-256',
            },
        );
        const tamperedEnvelope = {
            ...envelope,
            ciphertext: `${envelope.ciphertext.slice(0, -2)}00`,
        };

        await expect(
            verifyComplaintPrecondition(
                recipient.transportPrivateKeyHex,
                recipient.transportPublicKeyHex,
                'P-256',
            ),
        ).resolves.toBe(true);
        await expect(
            decryptEnvelope(tamperedEnvelope, recipient.transportPrivateKeyHex),
        ).rejects.toThrow();
        await expect(
            resolveDealerChallenge(
                tamperedEnvelope,
                recipient.transportPrivateKeyHex,
                ephemeralPrivateKey,
            ),
        ).resolves.toEqual({
            valid: false,
            fault: 'dealer',
        });

        const encryptedSharePayload = await signPayload(
            dealer.auth.privateKey,
            {
                sessionId,
                manifestHash,
                phase: 1,
                participantIndex: dealer.index,
                messageType: 'encrypted-dual-share',
                recipientIndex: recipient.index,
                envelopeId: tamperedEnvelope.envelopeId,
                suite: tamperedEnvelope.suite,
                ephemeralPublicKey: tamperedEnvelope.ephemeralPublicKey,
                iv: tamperedEnvelope.iv,
                ciphertext: tamperedEnvelope.ciphertext,
            } satisfies EncryptedDualSharePayload,
        );
        const complaintPayload = await signPayload(recipient.auth.privateKey, {
            sessionId,
            manifestHash,
            phase: 2,
            participantIndex: recipient.index,
            messageType: 'complaint',
            dealerIndex: dealer.index,
            envelopeId: tamperedEnvelope.envelopeId,
            reason: 'aes-gcm-failure',
        } satisfies ComplaintPayload);

        await expect(
            verifySignedPayload(dealer, encryptedSharePayload),
        ).resolves.toBe(true);
        await expect(
            verifySignedPayload(recipient, complaintPayload),
        ).resolves.toBe(true);

        const finalState = replayGjkrTranscript(
            {
                protocol: 'gjkr',
                sessionId,
                manifestHash,
                group: group.name,
                participantCount: 3,
                threshold: 3,
            },
            [
                ...registrations,
                ...acceptances,
                ...pedersenPayloads,
                encryptedSharePayload,
                complaintPayload,
            ],
        );

        expect(finalState.phase).toBe('aborted');
        expect(finalState.abortReason).toBe('qual-too-small');
        expect(finalState.qual).toEqual([2, 3]);
        expect(finalState.complaints).toHaveLength(1);
        expect(finalState.complaints[0].dealerIndex).toBe(1);
    });
});
