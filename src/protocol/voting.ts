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
import { fixedHexToBigint } from '../serialize/index.js';
import {
    combineDecryptionShares,
    type DecryptionShare,
} from '../threshold/index.js';

import {
    verifyAndAggregateBallots,
    type BallotTranscriptEntry,
    type VerifiedBallotAggregation,
} from './ballots.js';
import { hashElectionManifest, validateElectionManifest } from './manifest.js';
import type {
    BallotSubmissionPayload,
    DecryptionSharePayload,
    ElectionManifest,
    EncodedCiphertext,
    EncodedCompactProof,
    EncodedDisjunctiveProof,
    ProtocolPayload,
    SignedPayload,
    TallyPublicationPayload,
} from './types.js';
import { verifySignedProtocolPayloads } from './verification.js';

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
    c1: ciphertext.c1.toString(16).padStart(byteLength * 2, '0'),
    c2: ciphertext.c2.toString(16).padStart(byteLength * 2, '0'),
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
    challenge: proof.challenge.toString(16).padStart(byteLength * 2, '0'),
    response: proof.response.toString(16).padStart(byteLength * 2, '0'),
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
): BallotTranscriptEntry => {
    assertPhase(payload, BALLOT_SUBMISSION_PHASE, 'Ballot submission');
    assertPositiveParticipantIndex(payload.optionIndex);

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
});

/** Input bundle for verifying typed ballot payloads. */
export type VerifyBallotSubmissionPayloadsInput = {
    readonly ballotPayloads: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly publicKey: bigint;
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
};

/**
 * Verifies typed ballot-submission payloads and recomputes the aggregate tally
 * ciphertext from the accepted ballot transcript.
 *
 * Signatures are expected to have been checked already against the frozen
 * registration roster.
 *
 * @param input Typed ballot verification input.
 * @returns Verified additive ballot aggregation.
 */
export const verifyBallotSubmissionPayloads = async (
    input: VerifyBallotSubmissionPayloadsInput,
): Promise<VerifiedBallotAggregation> => {
    const manifest = validateElectionManifest(input.manifest);
    const manifestHash = await hashElectionManifest(manifest);
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

        return decodeBallotPayload(payload.payload);
    });

    return verifyAndAggregateBallots({
        ballots: ballotEntries,
        publicKey: input.publicKey,
        validValues: manifestScoreDomain(manifest),
        group: getGroup(input.manifest.suiteId),
        manifestHash,
        sessionId: input.sessionId,
        minimumBallotCount: manifest.minimumPublicationThreshold,
    });
};

/** Verified typed decryption-share payload. */
export type VerifiedDecryptionSharePayload = {
    readonly payload: SignedPayload<DecryptionSharePayload>;
    readonly share: DecryptionShare;
};

/** Input bundle for verifying typed decryption-share payloads. */
export type VerifyDecryptionSharePayloadsInput = {
    readonly aggregate: VerifiedBallotAggregation['aggregate'];
    readonly dkg: VerifiedDKGTranscript;
    readonly decryptionSharePayloads: readonly SignedPayload<DecryptionSharePayload>[];
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
};

/**
 * Verifies typed decryption-share payloads against the DKG transcript-derived
 * trustee keys and one locally recomputed aggregate ciphertext.
 *
 * Signatures are expected to have been checked already against the frozen
 * registration roster.
 *
 * @param input Typed decryption-share verification input.
 * @returns Verified decryption shares ready for threshold recombination.
 */
export const verifyDecryptionSharePayloads = async (
    input: VerifyDecryptionSharePayloadsInput,
): Promise<readonly VerifiedDecryptionSharePayload[]> => {
    const manifest = validateElectionManifest(input.manifest);
    const manifestHash = await hashElectionManifest(manifest);
    const qualSet = new Set(input.dkg.qual);

    if (input.decryptionSharePayloads.length < manifest.threshold) {
        throw new InvalidPayloadError(
            `At least ${manifest.threshold} decryption shares are required`,
        );
    }

    const verifiedShares: VerifiedDecryptionSharePayload[] = [];
    for (const signedPayload of input.decryptionSharePayloads) {
        const payload = signedPayload.payload;
        assertPhase(payload, DECRYPTION_SHARE_PHASE, 'Decryption share');
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
        assertNonEmptyString(
            payload.transcriptHash,
            'Decryption transcript hash',
        );
        if (payload.transcriptHash !== input.aggregate.transcriptHash) {
            throw new InvalidPayloadError(
                `Decryption share transcript hash mismatch for participant ${payload.participantIndex}`,
            );
        }
        if (payload.ballotCount !== input.aggregate.ballotCount) {
            throw new InvalidPayloadError(
                `Decryption share ballot count mismatch for participant ${payload.participantIndex}`,
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
            ciphertext: input.aggregate.ciphertext,
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
                `Decryption-share proof failed verification for participant ${payload.participantIndex}`,
            );
        }

        verifiedShares.push({
            payload: signedPayload,
            share: decryptionShare,
        });
    }

    return verifiedShares;
};

/** Input bundle for verifying one full published tally. */
export type VerifyPublishedVotingResultInput = {
    readonly protocol: DKGProtocol;
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
    readonly dkgTranscript: readonly SignedPayload[];
    readonly ballotPayloads: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly decryptionSharePayloads: readonly SignedPayload<DecryptionSharePayload>[];
    readonly tallyPublication?: SignedPayload<TallyPublicationPayload>;
};

/** Verified published tally and all of its reusable sub-results. */
export type VerifiedPublishedVotingResult = {
    readonly dkg: VerifiedDKGTranscript;
    readonly ballots: VerifiedBallotAggregation;
    readonly decryptionShares: readonly VerifiedDecryptionSharePayload[];
    readonly tally: bigint;
};

/**
 * Verifies one published tally from the signed DKG log, typed ballot payloads,
 * typed decryption-share payloads, and an optional tally-publication record.
 *
 * The helper intentionally recomputes everything locally: it verifies the DKG
 * transcript, recomputes the aggregate from the accepted ballots, verifies each
 * DLEQ proof against transcript-derived trustee keys, and only then combines
 * shares into the final tally.
 *
 * @param input Published tally verification input.
 * @returns Fully verified tally result.
 */
export const verifyPublishedVotingResult = async (
    input: VerifyPublishedVotingResultInput,
): Promise<VerifiedPublishedVotingResult> => {
    const manifest = validateElectionManifest(input.manifest);
    const dkg = await verifyDKGTranscript({
        protocol: input.protocol,
        transcript: input.dkgTranscript,
        manifest,
        sessionId: input.sessionId,
    });

    await verifySignedProtocolPayloads(
        [
            ...input.dkgTranscript,
            ...input.ballotPayloads,
            ...input.decryptionSharePayloads,
            ...(input.tallyPublication === undefined
                ? []
                : [input.tallyPublication]),
        ],
        manifest.participantCount,
    );

    const ballots = await verifyBallotSubmissionPayloads({
        ballotPayloads: input.ballotPayloads,
        publicKey: dkg.derivedPublicKey,
        manifest,
        sessionId: input.sessionId,
    });
    const decryptionShares = await verifyDecryptionSharePayloads({
        aggregate: ballots.aggregate,
        dkg,
        decryptionSharePayloads: input.decryptionSharePayloads,
        manifest,
        sessionId: input.sessionId,
    });
    const bound =
        BigInt(ballots.aggregate.ballotCount) * BigInt(manifest.scoreDomainMax);
    const tally = combineDecryptionShares(
        ballots.aggregate.ciphertext,
        decryptionShares.map((entry) => entry.share),
        dkg.group,
        bound,
    );

    if (input.tallyPublication !== undefined) {
        const payload = input.tallyPublication.payload;
        assertPhase(payload, TALLY_PUBLICATION_PHASE, 'Tally publication');
        if (payload.sessionId !== input.sessionId) {
            throw new InvalidPayloadError(
                'Tally publication session does not match the verification input',
            );
        }
        const manifestHash = await hashElectionManifest(manifest);
        if (payload.manifestHash !== manifestHash) {
            throw new InvalidPayloadError(
                'Tally publication manifest hash does not match the verification input',
            );
        }
        if (payload.transcriptHash !== ballots.aggregate.transcriptHash) {
            throw new InvalidPayloadError(
                'Tally publication transcript hash does not match the accepted ballot transcript',
            );
        }
        if (payload.ballotCount !== ballots.aggregate.ballotCount) {
            throw new InvalidPayloadError(
                'Tally publication ballot count does not match the accepted ballot transcript',
            );
        }
        if (fixedHexToBigint(payload.tally) !== tally) {
            throw new InvalidPayloadError(
                'Tally publication does not match the recomputed tally',
            );
        }
        assertUniqueSortedIndices(
            payload.decryptionParticipantIndices,
            'Tally publication decryption participant',
        );
        const actualIndices = decryptionShares
            .map((entry) => entry.share.index)
            .sort((left, right) => left - right);
        if (
            JSON.stringify(payload.decryptionParticipantIndices) !==
            JSON.stringify(actualIndices)
        ) {
            throw new InvalidPayloadError(
                'Tally publication decryption participant set does not match the supplied decryption shares',
            );
        }
    }

    return {
        dkg,
        ballots,
        decryptionShares,
        tally,
    };
};
