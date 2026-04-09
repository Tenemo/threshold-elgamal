import { createDeterministicSource } from '../../../helpers/deterministic.js';

import {
    createComplaintResolutionPayload,
    invariant,
    parseShareEnvelope,
    signPayload,
} from './common.js';
import type {
    ComplaintInjection,
    DealerMaterial,
    ParticipantRuntime,
} from './types.js';

import { modQ, utf8ToBytes, type CryptoGroup } from '#core';
import {
    createSchnorrProof,
    verifySchnorrProof,
    type ProofContext,
} from '#proofs';
import {
    canonicalizeJson,
    type ComplaintPayload,
    type ComplaintResolutionPayload,
    type EncryptedDualSharePayload,
    type SignedPayload,
} from '#protocol';
import { bigintToFixedHex } from '#serialize';
import {
    decryptEnvelope,
    encryptEnvelope,
    resolveDealerChallenge,
    verifyComplaintPrecondition,
    type ComplaintResolution,
    type EncryptedEnvelope,
} from '#transport';
import {
    derivePedersenShares,
    generateFeldmanCommitments,
    generatePedersenCommitments,
    verifyFeldmanShare,
    verifyPedersenShare,
} from '#vss';

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

export const buildDealerMaterial = async (
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
                protocolVersion: 'v1',
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
                    {
                        postCallOffset: 17,
                    },
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
                        protocolVersion: 'v1',
                        suite: recipient.transportSuite,
                    },
                );
                const decrypted = await decryptEnvelope(
                    envelope,
                    recipient.transportPrivateKey,
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
                        recipient.transportPrivateKey,
                        recipient.transportPublicKeyHex,
                        recipient.transportSuite,
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
                };
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
                    bigintToFixedHex(value, group.byteLength),
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
                    bigintToFixedHex(value, group.byteLength),
                ),
                proofs: schnorrProofs.map((proof) => ({
                    coefficientIndex: proof.coefficientIndex,
                    challenge: bigintToFixedHex(
                        proof.challenge,
                        group.byteLength,
                    ),
                    response: bigintToFixedHex(
                        proof.response,
                        group.byteLength,
                    ),
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
    invariant(tamper !== undefined, 'Expected an envelope tamper mode');

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
        default:
            throw new Error('Unsupported envelope tamper mode');
    }
};

type ComplaintArtifacts = {
    readonly allEncryptedSharePayloads: readonly SignedPayload<EncryptedDualSharePayload>[];
    readonly complainedDealerIndices: ReadonlySet<number>;
    readonly complaintPayloads: readonly SignedPayload<ComplaintPayload>[];
    readonly complaintResolutionPayloads: readonly SignedPayload<ComplaintResolutionPayload>[];
    readonly complaintResolutions: readonly (ComplaintResolution & {
        readonly dealerIndex: number;
        readonly recipientIndex: number;
    })[];
};

export const buildComplaintArtifacts = async (
    complaints: readonly ComplaintInjection[] | undefined,
    dealerMaterials: readonly DealerMaterial[],
    participants: readonly ParticipantRuntime[],
    sessionId: string,
    manifestHash: string,
): Promise<ComplaintArtifacts> => {
    const complaintResolutions: (ComplaintResolution & {
        readonly dealerIndex: number;
        readonly recipientIndex: number;
    })[] = [];
    const complaintPayloads: SignedPayload<ComplaintPayload>[] = [];
    const complaintResolutionPayloads: SignedPayload<ComplaintResolutionPayload>[] =
        [];
    const complainedDealerIndices = new Set<number>();
    const tamperedEnvelopePayloads = new Map<
        string,
        SignedPayload<EncryptedDualSharePayload>
    >();

    for (const complaint of complaints ?? []) {
        const resolutionOutcome = complaint.resolutionOutcome ?? 'dealer-fault';
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
                recipient.transportPrivateKey,
                recipient.transportPublicKeyHex,
                recipient.transportSuite,
            ),
            `Complaint precondition failed for participant ${complaint.recipientIndex}`,
        );

        if (resolutionOutcome === 'dealer-fault') {
            invariant(
                complaint.envelopeTamper !== undefined,
                'Dealer-fault complaints require a tampered envelope field',
            );

            const tamperedEnvelope = tamperEnvelope(
                envelopeArtifact.envelope,
                complaint.envelopeTamper,
            );

            await decryptEnvelope(
                tamperedEnvelope,
                recipient.transportPrivateKey,
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
                recipient.transportPrivateKey,
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
        } else {
            invariant(
                complaint.envelopeTamper === undefined,
                'Complainant-fault complaints must reference the untampered envelope',
            );

            const resolution = await resolveDealerChallenge(
                envelopeArtifact.envelope,
                recipient.transportPrivateKey,
                envelopeArtifact.ephemeralPrivateKey,
            );
            complaintResolutions.push({
                ...resolution,
                dealerIndex: complaint.dealerIndex,
                recipientIndex: complaint.recipientIndex,
            });
            invariant(
                resolution.valid === true &&
                    resolution.fault === 'complainant' &&
                    resolution.plaintext !== undefined,
                `Expected complainant fault for complaint against dealer ${complaint.dealerIndex}`,
            );

            complaintResolutionPayloads.push(
                await createComplaintResolutionPayload(
                    participants[complaint.dealerIndex - 1],
                    sessionId,
                    manifestHash,
                    complaint.recipientIndex,
                    envelopeArtifact,
                ),
            );
        }

        const referencedEnvelopeId =
            resolutionOutcome === 'dealer-fault'
                ? tamperedEnvelopePayloads.get(
                      `${complaint.dealerIndex}:${complaint.recipientIndex}`,
                  )?.payload.envelopeId
                : envelopeArtifact.envelope.envelopeId;
        invariant(
            referencedEnvelopeId !== undefined,
            `Missing complaint envelope id for dealer ${complaint.dealerIndex} and recipient ${complaint.recipientIndex}`,
        );
        complaintPayloads.push(
            await signPayload(recipient.auth.privateKey, {
                sessionId,
                manifestHash,
                phase: 2,
                participantIndex: recipient.index,
                messageType: 'complaint',
                dealerIndex: complaint.dealerIndex,
                envelopeId: referencedEnvelopeId,
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

    return {
        allEncryptedSharePayloads,
        complainedDealerIndices,
        complaintPayloads,
        complaintResolutionPayloads,
        complaintResolutions,
    };
};
