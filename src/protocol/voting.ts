import {
    assertPositiveParticipantIndex,
    getGroup,
    InvalidPayloadError,
    type CryptoGroup,
} from '../core/index.js';
import type { DKGProtocol } from '../dkg/types.js';
import {
    deriveTranscriptVerificationKey,
    verifyDKGTranscript,
    type VerifiedDKGTranscript,
} from '../dkg/verification.js';
import { verifyDLEQProof, type DLEQStatement } from '../proofs/dleq.js';
import type {
    DLEQProof,
    DisjunctiveProof,
    ProofContext,
} from '../proofs/types.js';
import { bigintToFixedHex, fixedHexToBigint } from '../serialize/index.js';
import {
    combineDecryptionShares,
    type DecryptionShare,
} from '../threshold/index.js';
import {
    importAuthPublicKey,
    verifyPayloadSignature,
} from '../transport/auth.js';

import {
    verifyAndAggregateBallotsByOption,
    type BallotTranscriptEntry,
    type VerifiedBallotAggregation,
    type VerifiedOptionBallotAggregation,
} from './ballots.js';
import { hashElectionManifest, validateElectionManifest } from './manifest.js';
import { canonicalUnsignedPayloadBytes } from './payloads.js';
import type {
    BallotSubmissionPayload,
    DecryptionSharePayload,
    ElectionManifest,
    EncodedCiphertext,
    EncodedCompactProof,
    EncodedDisjunctiveProof,
    ProtocolPayload,
    RegistrationPayload,
    SignedPayload,
    TallyPublicationPayload,
} from './types.js';

const BALLOT_SUBMISSION_PHASE = 5;
const DECRYPTION_SHARE_PHASE = 6;
const TALLY_PUBLICATION_PHASE = 7;

const assertPhase = (
    payload: ProtocolPayload,
    expectedPhase: number,
    label: string,
): void => {
    if (payload.phase !== expectedPhase) {
        throw new InvalidPayloadError(
            `${label} payload phase must equal ${expectedPhase}`,
        );
    }
};

const assertNonEmptyString = (value: string, label: string): void => {
    if (value.trim() === '') {
        throw new InvalidPayloadError(`${label} must be a non-empty string`);
    }
};

const assertUniqueSortedIndices = (
    indices: readonly number[],
    label: string,
): void => {
    let previous = 0;
    const seen = new Set<number>();

    for (const index of indices) {
        assertPositiveParticipantIndex(index);
        if (seen.has(index)) {
            throw new InvalidPayloadError(`${label} indices must be unique`);
        }
        if (index <= previous) {
            throw new InvalidPayloadError(
                `${label} indices must be strictly increasing`,
            );
        }
        seen.add(index);
        previous = index;
    }
};

const assertValidOptionIndex = (
    optionIndex: number,
    optionCount: number,
    label: string,
): void => {
    if (!Number.isInteger(optionIndex) || optionIndex < 1) {
        throw new InvalidPayloadError(
            `${label} option index must be a positive integer`,
        );
    }

    if (optionIndex > optionCount) {
        throw new InvalidPayloadError(
            `${label} option index ${optionIndex} exceeds the manifest option count ${optionCount}`,
        );
    }
};

const assertSingleOptionManifest = (
    manifest: ElectionManifest,
    label: string,
): void => {
    if (manifest.optionList.length !== 1) {
        throw new InvalidPayloadError(
            `${label} requires a single-option manifest; use the per-option verification helpers instead`,
        );
    }
};

/**
 * Encodes an additive ciphertext into fixed-width protocol hex.
 *
 * @param ciphertext Ciphertext to encode.
 * @param byteLength Fixed group byte width.
 * @returns Protocol ciphertext encoding.
 */
export const encodeCiphertext = (
    ciphertext: { readonly c1: bigint; readonly c2: bigint },
    byteLength: number,
): EncodedCiphertext => ({
    c1: bigintToFixedHex(ciphertext.c1, byteLength),
    c2: bigintToFixedHex(ciphertext.c2, byteLength),
});

/**
 * Decodes a protocol ciphertext into bigint components.
 *
 * @param ciphertext Protocol ciphertext encoding.
 * @returns Decoded ciphertext.
 */
export const decodeCiphertext = (
    ciphertext: EncodedCiphertext,
): { readonly c1: bigint; readonly c2: bigint } => ({
    c1: fixedHexToBigint(ciphertext.c1),
    c2: fixedHexToBigint(ciphertext.c2),
});

/**
 * Encodes a compact challenge-response proof into fixed-width protocol hex.
 *
 * @param proof Compact proof to encode.
 * @param byteLength Fixed group byte width.
 * @returns Protocol proof encoding.
 */
export const encodeCompactProof = (
    proof: { readonly challenge: bigint; readonly response: bigint },
    byteLength: number,
): EncodedCompactProof => ({
    challenge: bigintToFixedHex(proof.challenge, byteLength),
    response: bigintToFixedHex(proof.response, byteLength),
});

/**
 * Decodes a protocol compact proof into bigint fields.
 *
 * @param proof Protocol proof encoding.
 * @returns Decoded compact proof.
 */
export const decodeCompactProof = (proof: EncodedCompactProof): DLEQProof => ({
    challenge: fixedHexToBigint(proof.challenge),
    response: fixedHexToBigint(proof.response),
});

/**
 * Encodes a disjunctive proof into fixed-width protocol hex.
 *
 * @param proof Disjunctive proof to encode.
 * @param byteLength Fixed group byte width.
 * @returns Protocol proof encoding.
 */
export const encodeDisjunctiveProof = (
    proof: DisjunctiveProof,
    byteLength: number,
): EncodedDisjunctiveProof => ({
    branches: proof.branches.map((branch) =>
        encodeCompactProof(branch, byteLength),
    ),
});

/**
 * Decodes a protocol disjunctive proof into bigint fields.
 *
 * @param proof Protocol proof encoding.
 * @returns Decoded disjunctive proof.
 */
export const decodeDisjunctiveProof = (
    proof: EncodedDisjunctiveProof,
): DisjunctiveProof => ({
    branches: proof.branches.map((branch) => decodeCompactProof(branch)),
});

/**
 * Builds the ordered score domain implied by the manifest.
 *
 * @param manifest Validated election manifest.
 * @returns Ordered valid additive score values.
 */
export const manifestScoreDomain = (
    manifest: ElectionManifest,
): readonly bigint[] => {
    validateElectionManifest(manifest);

    return Array.from(
        {
            length: manifest.scoreDomainMax - manifest.scoreDomainMin + 1,
        },
        (_value, index) => BigInt(manifest.scoreDomainMin + index),
    );
};

const decodeBallotPayload = (
    payload: BallotSubmissionPayload,
    optionCount: number,
): BallotTranscriptEntry => {
    assertPhase(payload, BALLOT_SUBMISSION_PHASE, 'Ballot submission');
    assertValidOptionIndex(
        payload.optionIndex,
        optionCount,
        'Ballot submission',
    );

    return {
        voterIndex: payload.participantIndex,
        optionIndex: payload.optionIndex,
        ciphertext: decodeCiphertext(payload.ciphertext),
        proof: decodeDisjunctiveProof(payload.proof),
    };
};

const decryptionProofContext = (
    payload: DecryptionSharePayload,
    group: CryptoGroup,
): ProofContext => ({
    protocolVersion: 'v1',
    suiteId: group.name,
    manifestHash: payload.manifestHash,
    sessionId: payload.sessionId,
    label: 'decryption-share-dleq',
    participantIndex: payload.participantIndex,
    optionIndex: payload.optionIndex,
});

const verifyPayloadsAgainstRegistrations = async (
    payloads: readonly SignedPayload[],
    registrations: readonly SignedPayload<RegistrationPayload>[],
): Promise<void> => {
    const authKeyMap = new Map<number, CryptoKey>();

    for (const registration of registrations) {
        authKeyMap.set(
            registration.payload.participantIndex,
            await importAuthPublicKey(registration.payload.authPublicKey),
        );
    }

    for (const payload of payloads) {
        const publicKey = authKeyMap.get(payload.payload.participantIndex);
        if (publicKey === undefined) {
            throw new InvalidPayloadError(
                `Missing registration for participant ${payload.payload.participantIndex}`,
            );
        }

        const valid = await verifyPayloadSignature(
            publicKey,
            canonicalUnsignedPayloadBytes(payload.payload),
            payload.signature,
        );
        if (!valid) {
            throw new InvalidPayloadError(
                `Payload signature failed verification for participant ${payload.payload.participantIndex} (${payload.payload.messageType})`,
            );
        }
    }
};

const buildOptionAggregateMap = (
    aggregates: readonly OptionAggregateInput[],
    optionCount: number,
): ReadonlyMap<number, OptionAggregateInput> => {
    const aggregateMap = new Map<number, OptionAggregateInput>();

    for (const aggregate of aggregates) {
        assertValidOptionIndex(aggregate.optionIndex, optionCount, 'Aggregate');
        if (aggregateMap.has(aggregate.optionIndex)) {
            throw new InvalidPayloadError(
                `Duplicate aggregate for option ${aggregate.optionIndex} is not allowed`,
            );
        }
        aggregateMap.set(aggregate.optionIndex, aggregate);
    }

    for (let optionIndex = 1; optionIndex <= optionCount; optionIndex += 1) {
        if (!aggregateMap.has(optionIndex)) {
            throw new InvalidPayloadError(
                `Missing verified aggregate for option ${optionIndex}`,
            );
        }
    }

    return aggregateMap;
};

/**
 * Input bundle for verifying typed ballot payloads.
 */
export type VerifyBallotSubmissionPayloadsInput = {
    readonly ballotPayloads: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly publicKey: bigint;
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
};

/** Input bundle for verifying typed ballot payloads across all options. */
export type VerifyBallotSubmissionPayloadsByOptionInput =
    VerifyBallotSubmissionPayloadsInput;

/**
 * Verifies typed ballot-submission payloads and recomputes one aggregate tally
 * ciphertext per manifest option.
 *
 * Signatures are expected to have been checked already against the frozen
 * registration roster.
 *
 * @param input Typed ballot verification input.
 * @returns Ordered per-option additive ballot aggregations.
 */
export const verifyBallotSubmissionPayloadsByOption = async (
    input: VerifyBallotSubmissionPayloadsByOptionInput,
): Promise<readonly VerifiedOptionBallotAggregation[]> => {
    const manifest = validateElectionManifest(input.manifest);
    const manifestHash = await hashElectionManifest(manifest);
    const optionCount = manifest.optionList.length;
    const ballotEntries = input.ballotPayloads.map((payload) => {
        if (payload.payload.sessionId !== input.sessionId) {
            throw new InvalidPayloadError(
                'Ballot submission payload session does not match the verification input',
            );
        }
        if (payload.payload.manifestHash !== manifestHash) {
            throw new InvalidPayloadError(
                'Ballot submission payload manifest hash does not match the verification input',
            );
        }

        return decodeBallotPayload(payload.payload, optionCount);
    });

    return verifyAndAggregateBallotsByOption({
        ballots: ballotEntries,
        publicKey: input.publicKey,
        validValues: manifestScoreDomain(manifest),
        group: getGroup(input.manifest.suiteId),
        manifestHash,
        sessionId: input.sessionId,
        minimumBallotCount: manifest.minimumPublicationThreshold,
        optionCount,
    });
};

/**
 * Verifies typed ballot-submission payloads and recomputes the aggregate tally
 * ciphertext for a single-option manifest.
 *
 * @param input Typed ballot verification input.
 * @returns Verified additive ballot aggregation.
 */
export const verifyBallotSubmissionPayloads = async (
    input: VerifyBallotSubmissionPayloadsInput,
): Promise<VerifiedBallotAggregation> => {
    const manifest = validateElectionManifest(input.manifest);
    assertSingleOptionManifest(manifest, 'verifyBallotSubmissionPayloads');

    const aggregations = await verifyBallotSubmissionPayloadsByOption({
        ...input,
        manifest,
    });

    return aggregations[0];
};

/** Verified typed decryption-share payload. */
export type VerifiedDecryptionSharePayload = {
    readonly payload: SignedPayload<DecryptionSharePayload>;
    readonly share: DecryptionShare;
};

/** Verified aggregate input for one option slot. */
export type OptionAggregateInput = {
    readonly optionIndex: number;
    readonly aggregate: VerifiedBallotAggregation['aggregate'];
};

/** Verified decryption shares grouped by option slot. */
export type VerifiedOptionDecryptionShares = {
    readonly optionIndex: number;
    readonly decryptionShares: readonly VerifiedDecryptionSharePayload[];
};

/** Input bundle for verifying typed decryption-share payloads. */
export type VerifyDecryptionSharePayloadsInput = {
    readonly aggregate: VerifiedBallotAggregation['aggregate'];
    readonly dkg: VerifiedDKGTranscript;
    readonly decryptionSharePayloads: readonly SignedPayload<DecryptionSharePayload>[];
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
};

/** Input bundle for verifying typed decryption-share payloads by option. */
export type VerifyDecryptionSharePayloadsByOptionInput = {
    readonly aggregates: readonly OptionAggregateInput[];
    readonly dkg: VerifiedDKGTranscript;
    readonly decryptionSharePayloads: readonly SignedPayload<DecryptionSharePayload>[];
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
};

/**
 * Verifies typed decryption-share payloads against the DKG transcript-derived
 * trustee keys and one locally recomputed aggregate ciphertext per option slot.
 *
 * Signatures are expected to have been checked already against the frozen
 * registration roster.
 *
 * @param input Typed decryption-share verification input.
 * @returns Verified decryption shares grouped by option.
 */
export const verifyDecryptionSharePayloadsByOption = async (
    input: VerifyDecryptionSharePayloadsByOptionInput,
): Promise<readonly VerifiedOptionDecryptionShares[]> => {
    const manifest = validateElectionManifest(input.manifest);
    const manifestHash = await hashElectionManifest(manifest);
    const qualSet = new Set(input.dkg.qual);
    const optionCount = manifest.optionList.length;
    const aggregateMap = buildOptionAggregateMap(input.aggregates, optionCount);
    const payloadsByOption = new Map<
        number,
        SignedPayload<DecryptionSharePayload>[]
    >();

    for (let optionIndex = 1; optionIndex <= optionCount; optionIndex += 1) {
        payloadsByOption.set(optionIndex, []);
    }

    for (const signedPayload of input.decryptionSharePayloads) {
        const payload = signedPayload.payload;
        assertPhase(payload, DECRYPTION_SHARE_PHASE, 'Decryption share');
        assertValidOptionIndex(
            payload.optionIndex,
            optionCount,
            'Decryption share',
        );
        payloadsByOption.get(payload.optionIndex)?.push(signedPayload);
    }

    const verifiedShares: VerifiedOptionDecryptionShares[] = [];
    for (let optionIndex = 1; optionIndex <= optionCount; optionIndex += 1) {
        const optionAggregate = aggregateMap.get(optionIndex);
        const optionPayloads = payloadsByOption.get(optionIndex) ?? [];

        if (optionAggregate === undefined) {
            throw new InvalidPayloadError(
                `Missing verified aggregate for option ${optionIndex}`,
            );
        }
        if (optionPayloads.length < manifest.threshold) {
            throw new InvalidPayloadError(
                `At least ${manifest.threshold} decryption shares are required for option ${optionIndex}`,
            );
        }

        const seenParticipants = new Set<number>();
        const optionVerifiedShares: VerifiedDecryptionSharePayload[] = [];
        for (const signedPayload of optionPayloads) {
            const payload = signedPayload.payload;
            if (payload.sessionId !== input.sessionId) {
                throw new InvalidPayloadError(
                    'Decryption-share payload session does not match the verification input',
                );
            }
            if (payload.manifestHash !== manifestHash) {
                throw new InvalidPayloadError(
                    'Decryption-share payload manifest hash does not match the verification input',
                );
            }
            if (!qualSet.has(payload.participantIndex)) {
                throw new InvalidPayloadError(
                    `Decryption share came from non-qualified participant ${payload.participantIndex}`,
                );
            }
            if (seenParticipants.has(payload.participantIndex)) {
                throw new InvalidPayloadError(
                    `Duplicate decryption share for participant ${payload.participantIndex} and option ${optionIndex} is not allowed`,
                );
            }
            seenParticipants.add(payload.participantIndex);

            assertNonEmptyString(
                payload.transcriptHash,
                'Decryption transcript hash',
            );
            if (
                payload.transcriptHash !==
                optionAggregate.aggregate.transcriptHash
            ) {
                throw new InvalidPayloadError(
                    `Decryption share transcript hash mismatch for participant ${payload.participantIndex} and option ${optionIndex}`,
                );
            }
            if (payload.ballotCount !== optionAggregate.aggregate.ballotCount) {
                throw new InvalidPayloadError(
                    `Decryption share ballot count mismatch for participant ${payload.participantIndex} and option ${optionIndex}`,
                );
            }

            const decryptionShare = {
                index: payload.participantIndex,
                value: fixedHexToBigint(payload.decryptionShare),
            } satisfies DecryptionShare;
            const statement: DLEQStatement = {
                publicKey: deriveTranscriptVerificationKey(
                    input.dkg.feldmanCommitments,
                    payload.participantIndex,
                    input.dkg.group,
                ),
                ciphertext: optionAggregate.aggregate.ciphertext,
                decryptionShare: decryptionShare.value,
            };
            const proof = decodeCompactProof(payload.proof);
            const valid = await verifyDLEQProof(
                proof,
                statement,
                input.dkg.group,
                decryptionProofContext(payload, input.dkg.group),
            );

            if (!valid) {
                throw new InvalidPayloadError(
                    `Decryption-share proof failed verification for participant ${payload.participantIndex} and option ${optionIndex}`,
                );
            }

            optionVerifiedShares.push({
                payload: signedPayload,
                share: decryptionShare,
            });
        }

        verifiedShares.push({
            optionIndex,
            decryptionShares: optionVerifiedShares,
        });
    }

    return verifiedShares;
};

/**
 * Verifies typed decryption-share payloads against the DKG transcript-derived
 * trustee keys and one locally recomputed aggregate ciphertext for a
 * single-option manifest.
 *
 * @param input Typed decryption-share verification input.
 * @returns Verified decryption shares ready for threshold recombination.
 */
export const verifyDecryptionSharePayloads = async (
    input: VerifyDecryptionSharePayloadsInput,
): Promise<readonly VerifiedDecryptionSharePayload[]> => {
    const manifest = validateElectionManifest(input.manifest);
    assertSingleOptionManifest(manifest, 'verifyDecryptionSharePayloads');

    const verifiedShares = await verifyDecryptionSharePayloadsByOption({
        aggregates: [
            {
                optionIndex: 1,
                aggregate: input.aggregate,
            },
        ],
        dkg: input.dkg,
        decryptionSharePayloads: input.decryptionSharePayloads,
        manifest,
        sessionId: input.sessionId,
    });

    return verifiedShares[0].decryptionShares;
};

/** Input bundle for verifying one published tally. */
export type VerifyPublishedVotingResultInput = {
    readonly protocol: DKGProtocol;
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
    readonly dkgTranscript: readonly SignedPayload[];
    readonly ballotPayloads: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly decryptionSharePayloads: readonly SignedPayload<DecryptionSharePayload>[];
    readonly tallyPublication?: SignedPayload<TallyPublicationPayload>;
};

/** Input bundle for verifying one full published tally set across all options. */
export type VerifyPublishedVotingResultsInput = {
    readonly protocol: DKGProtocol;
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
    readonly dkgTranscript: readonly SignedPayload[];
    readonly ballotPayloads: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly decryptionSharePayloads: readonly SignedPayload<DecryptionSharePayload>[];
    readonly tallyPublications?: readonly SignedPayload<TallyPublicationPayload>[];
};

/** Verified published tally for one option slot. */
export type VerifiedPublishedOptionVotingResult = {
    readonly optionIndex: number;
    readonly ballots: VerifiedOptionBallotAggregation;
    readonly decryptionShares: readonly VerifiedDecryptionSharePayload[];
    readonly tally: bigint;
};

/** Verified published tallies and reusable transcript sub-results. */
export type VerifiedPublishedVotingResults = {
    readonly dkg: VerifiedDKGTranscript;
    readonly options: readonly VerifiedPublishedOptionVotingResult[];
};

/** Verified published tally and all of its reusable sub-results. */
export type VerifiedPublishedVotingResult = {
    readonly dkg: VerifiedDKGTranscript;
    readonly ballots: VerifiedBallotAggregation;
    readonly decryptionShares: readonly VerifiedDecryptionSharePayload[];
    readonly tally: bigint;
};

/**
 * Verifies published tallies from the signed DKG log, typed ballot payloads,
 * typed decryption-share payloads, and optional tally-publication records.
 *
 * The helper intentionally recomputes everything locally: it verifies the DKG
 * transcript, recomputes one aggregate per option from the accepted ballots,
 * verifies each DLEQ proof against transcript-derived trustee keys, and only
 * then combines shares into the final tallies.
 *
 * @param input Published tally verification input.
 * @returns Fully verified per-option tally results.
 */
export const verifyPublishedVotingResults = async (
    input: VerifyPublishedVotingResultsInput,
): Promise<VerifiedPublishedVotingResults> => {
    const manifest = validateElectionManifest(input.manifest);
    const manifestHash = await hashElectionManifest(manifest);
    const dkg = await verifyDKGTranscript({
        protocol: input.protocol,
        transcript: input.dkgTranscript,
        manifest,
        sessionId: input.sessionId,
    });
    const optionCount = manifest.optionList.length;
    const tallyPublications =
        input.tallyPublications === undefined ||
        input.tallyPublications.length === 0
            ? undefined
            : input.tallyPublications;

    await verifyPayloadsAgainstRegistrations(
        [
            ...input.ballotPayloads,
            ...input.decryptionSharePayloads,
            ...(tallyPublications ?? []),
        ],
        dkg.registrations,
    );

    const ballots = await verifyBallotSubmissionPayloadsByOption({
        ballotPayloads: input.ballotPayloads,
        publicKey: dkg.derivedPublicKey,
        manifest,
        sessionId: input.sessionId,
    });
    const decryptionShares = await verifyDecryptionSharePayloadsByOption({
        aggregates: ballots.map((optionBallots) => ({
            optionIndex: optionBallots.optionIndex,
            aggregate: optionBallots.aggregate,
        })),
        dkg,
        decryptionSharePayloads: input.decryptionSharePayloads,
        manifest,
        sessionId: input.sessionId,
    });

    const tallyPublicationMap = new Map<
        number,
        SignedPayload<TallyPublicationPayload>
    >();
    if (tallyPublications !== undefined) {
        if (tallyPublications.length !== optionCount) {
            throw new InvalidPayloadError(
                `Expected ${optionCount} tally-publication payloads, received ${tallyPublications.length}`,
            );
        }

        for (const signedPayload of tallyPublications) {
            const payload = signedPayload.payload;
            assertPhase(payload, TALLY_PUBLICATION_PHASE, 'Tally publication');
            if (payload.sessionId !== input.sessionId) {
                throw new InvalidPayloadError(
                    'Tally publication session does not match the verification input',
                );
            }
            if (payload.manifestHash !== manifestHash) {
                throw new InvalidPayloadError(
                    'Tally publication manifest hash does not match the verification input',
                );
            }
            assertValidOptionIndex(
                payload.optionIndex,
                optionCount,
                'Tally publication',
            );
            if (tallyPublicationMap.has(payload.optionIndex)) {
                throw new InvalidPayloadError(
                    `Duplicate tally publication for option ${payload.optionIndex} is not allowed`,
                );
            }
            tallyPublicationMap.set(payload.optionIndex, signedPayload);
        }
    }

    const results: VerifiedPublishedOptionVotingResult[] = [];
    for (let optionIndex = 1; optionIndex <= optionCount; optionIndex += 1) {
        const optionBallots = ballots.find(
            (entry) => entry.optionIndex === optionIndex,
        );
        const optionDecryptionShares = decryptionShares.find(
            (entry) => entry.optionIndex === optionIndex,
        );

        if (optionBallots === undefined) {
            throw new InvalidPayloadError(
                `Missing verified ballots for option ${optionIndex}`,
            );
        }
        if (optionDecryptionShares === undefined) {
            throw new InvalidPayloadError(
                `Missing verified decryption shares for option ${optionIndex}`,
            );
        }

        const bound =
            BigInt(optionBallots.aggregate.ballotCount) *
            BigInt(manifest.scoreDomainMax);
        const tally = combineDecryptionShares(
            optionBallots.aggregate.ciphertext,
            optionDecryptionShares.decryptionShares.map((entry) => entry.share),
            dkg.group,
            bound,
        );

        const publication = tallyPublicationMap.get(optionIndex);
        if (tallyPublications !== undefined && publication === undefined) {
            throw new InvalidPayloadError(
                `Missing tally publication for option ${optionIndex}`,
            );
        }
        if (publication !== undefined) {
            const payload = publication.payload;

            if (
                payload.transcriptHash !==
                optionBallots.aggregate.transcriptHash
            ) {
                throw new InvalidPayloadError(
                    `Tally publication transcript hash does not match the accepted ballot transcript for option ${optionIndex}`,
                );
            }
            if (payload.ballotCount !== optionBallots.aggregate.ballotCount) {
                throw new InvalidPayloadError(
                    `Tally publication ballot count does not match the accepted ballot transcript for option ${optionIndex}`,
                );
            }
            if (fixedHexToBigint(payload.tally) !== tally) {
                throw new InvalidPayloadError(
                    `Tally publication does not match the recomputed tally for option ${optionIndex}`,
                );
            }
            assertUniqueSortedIndices(
                payload.decryptionParticipantIndices,
                'Tally publication decryption participant',
            );
            const actualIndices = optionDecryptionShares.decryptionShares
                .map((entry) => entry.share.index)
                .sort((left, right) => left - right);
            if (
                JSON.stringify(payload.decryptionParticipantIndices) !==
                JSON.stringify(actualIndices)
            ) {
                throw new InvalidPayloadError(
                    `Tally publication decryption participant set does not match the supplied decryption shares for option ${optionIndex}`,
                );
            }
        }

        results.push({
            optionIndex,
            ballots: optionBallots,
            decryptionShares: optionDecryptionShares.decryptionShares,
            tally,
        });
    }

    return {
        dkg,
        options: results,
    };
};

/**
 * Verifies one published tally from the signed DKG log, typed ballot payloads,
 * typed decryption-share payloads, and an optional tally-publication record for
 * a single-option manifest.
 *
 * @param input Published tally verification input.
 * @returns Fully verified tally result.
 */
export const verifyPublishedVotingResult = async (
    input: VerifyPublishedVotingResultInput,
): Promise<VerifiedPublishedVotingResult> => {
    const manifest = validateElectionManifest(input.manifest);
    assertSingleOptionManifest(manifest, 'verifyPublishedVotingResult');

    const results = await verifyPublishedVotingResults({
        protocol: input.protocol,
        manifest,
        sessionId: input.sessionId,
        dkgTranscript: input.dkgTranscript,
        ballotPayloads: input.ballotPayloads,
        decryptionSharePayloads: input.decryptionSharePayloads,
        tallyPublications:
            input.tallyPublication === undefined
                ? undefined
                : [input.tallyPublication],
    });
    const option = results.options[0];

    return {
        dkg: results.dkg,
        ballots: option.ballots,
        decryptionShares: option.decryptionShares,
        tally: option.tally,
    };
};
