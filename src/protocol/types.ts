/**
 * Public protocol payload and verification types.
 *
 * These types describe the signed board records that move through manifest
 * publication, DKG, ballot casting, decryption-share publication, and final
 * tally verification.
 */
import type { EncodedPoint } from '../core/types';
import type { VerifiedDKGTranscript } from '../dkg/verification';
import type { DecryptionShare } from '../threshold/types';
import type {
    EncodedAuthPublicKey,
    EncodedTransportPrivateKey,
    EncodedTransportPublicKey,
} from '../transport/types';

/**
 * Canonical protocol payload type identifiers for the supported ceremony.
 */
export type ProtocolMessageType =
    | 'manifest-publication'
    | 'registration'
    | 'manifest-acceptance'
    | 'phase-checkpoint'
    | 'pedersen-commitment'
    | 'encrypted-dual-share'
    | 'complaint'
    | 'complaint-resolution'
    | 'feldman-commitment'
    | 'key-derivation-confirmation'
    | 'ballot-submission'
    | 'ballot-close'
    | 'decryption-share'
    | 'tally-publication';

/** Complaint reasons recognized by the protocol layer. */
export type ComplaintReason =
    | 'aes-gcm-failure'
    | 'malformed-plaintext'
    | 'pedersen-failure';

/**
 * Shared fields present on every unsigned protocol payload.
 *
 * These fields bind each payload to one manifest, session, participant, and
 * protocol phase.
 */
export type BaseProtocolPayload = {
    readonly protocolVersion: string;
    readonly sessionId: string;
    readonly manifestHash: string;
    readonly phase: number;
    readonly participantIndex: number;
    readonly messageType: ProtocolMessageType;
};

/** Canonical additive ciphertext encoding used by protocol payloads. */
export type EncodedCiphertext = {
    readonly c1: string;
    readonly c2: string;
};

/** Canonical compact Schnorr or DLEQ proof encoding used by payloads. */
export type EncodedCompactProof = {
    readonly challenge: string;
    readonly response: string;
};

/** Canonical CDS94 proof branch encoding used by ballot payloads. */
export type EncodedDisjunctiveBranch = {
    readonly challenge: string;
    readonly response: string;
};

/** Canonical CDS94 proof encoding used by ballot payloads. */
export type EncodedDisjunctiveProof = {
    readonly branches: readonly EncodedDisjunctiveBranch[];
};

/**
 * Registration payload carrying ceremony auth and transport keys.
 *
 * This is the public source of truth for the accepted roster.
 */
export type RegistrationPayload = BaseProtocolPayload & {
    readonly messageType: 'registration';
    readonly rosterHash: string;
    readonly authPublicKey: EncodedAuthPublicKey;
    readonly transportPublicKey: EncodedTransportPublicKey;
};

/**
 * Participant-signed manifest acceptance payload.
 *
 * This records acceptance of the frozen manifest and roster hash for one
 * assigned participant index.
 */
export type ManifestAcceptancePayload = BaseProtocolPayload & {
    readonly messageType: 'manifest-acceptance';
    readonly rosterHash: string;
    readonly assignedParticipantIndex: number;
    readonly accountIdHash?: string;
};

/** Signed checkpoint payload that closes one DKG epoch on a threshold-supported shared snapshot. */
export type PhaseCheckpointPayload = BaseProtocolPayload & {
    readonly messageType: 'phase-checkpoint';
    readonly checkpointPhase: 0 | 1 | 2 | 3;
    readonly checkpointTranscriptHash: string;
    readonly qualifiedParticipantIndices: readonly number[];
};

/**
 * Broadcast payload carrying Pedersen coefficient commitments.
 *
 * This belongs to DKG phase 1.
 */
export type PedersenCommitmentPayload = BaseProtocolPayload & {
    readonly messageType: 'pedersen-commitment';
    readonly commitments: readonly string[];
};

/**
 * Encrypted share-envelope payload for the share-distribution step.
 *
 * This publishes the sender-ephemeral envelope metadata for one dealer to one
 * recipient in DKG phase 1.
 */
export type EncryptedDualSharePayload = BaseProtocolPayload & {
    readonly messageType: 'encrypted-dual-share';
    readonly recipientIndex: number;
    readonly envelopeId: string;
    readonly suite: 'X25519';
    readonly ephemeralPublicKey: EncodedTransportPublicKey;
    readonly iv: string;
    readonly ciphertext: string;
};

/** Complaint payload against a dealer envelope or share. */
export type ComplaintPayload = BaseProtocolPayload & {
    readonly messageType: 'complaint';
    readonly dealerIndex: number;
    readonly envelopeId: string;
    readonly reason: ComplaintReason;
};

/**
 * Dealer-signed complaint-resolution payload carrying the sender-ephemeral
 * private key that lets every verifier independently resolve one complaint.
 */
export type ComplaintResolutionPayload = BaseProtocolPayload & {
    readonly messageType: 'complaint-resolution';
    readonly dealerIndex: number;
    readonly complainantIndex: number;
    readonly envelopeId: string;
    readonly suite: 'X25519';
    readonly revealedEphemeralPrivateKey: EncodedTransportPrivateKey;
};

/**
 * Broadcast payload carrying Feldman commitments and coefficient proofs.
 *
 * This belongs to DKG phase 3.
 */
export type FeldmanCommitmentPayload = BaseProtocolPayload & {
    readonly messageType: 'feldman-commitment';
    readonly commitments: readonly string[];
    readonly proofs: readonly {
        readonly coefficientIndex: number;
        readonly challenge: string;
        readonly response: string;
    }[];
};

/**
 * Final key-derivation confirmation payload for the derived joint key.
 */
export type KeyDerivationConfirmation = BaseProtocolPayload & {
    readonly messageType: 'key-derivation-confirmation';
    readonly dkgTranscriptHash: string;
    readonly publicKey: EncodedPoint;
};

/**
 * Signed manifest-publication payload anchoring the frozen manifest.
 *
 * This is the first public payload in the supported ceremony.
 */
export type ManifestPublicationPayload = BaseProtocolPayload & {
    readonly messageType: 'manifest-publication';
    readonly manifest: ElectionManifest;
};

/**
 * Signed additive ballot payload for one participant and one option slot.
 *
 * A complete voter ballot is represented as one such payload per option.
 */
export type BallotSubmissionPayload = BaseProtocolPayload & {
    readonly messageType: 'ballot-submission';
    readonly optionIndex: number;
    readonly ciphertext: EncodedCiphertext;
    readonly proof: EncodedDisjunctiveProof;
};

/**
 * Signed organizer payload that freezes which participants are counted.
 *
 * This is the cutoff record that determines the accepted ballot set used for
 * tallying.
 */
export type BallotClosePayload = BaseProtocolPayload & {
    readonly messageType: 'ballot-close';
    readonly countedParticipantIndices: readonly number[];
};

/**
 * Signed threshold decryption-share payload tied to a locally recomputed
 * additive aggregate transcript.
 */
export type DecryptionSharePayload = BaseProtocolPayload & {
    readonly messageType: 'decryption-share';
    readonly optionIndex: number;
    readonly transcriptHash: string;
    readonly ballotCount: number;
    readonly decryptionShare: EncodedPoint;
    readonly proof: EncodedCompactProof;
};

/**
 * Signed tally-publication payload for the recovered additive tally.
 *
 * This is the optional published record checked against the verifier's own
 * recomputed tally.
 */
export type TallyPublicationPayload = BaseProtocolPayload & {
    readonly messageType: 'tally-publication';
    readonly optionIndex: number;
    readonly transcriptHash: string;
    readonly ballotCount: number;
    readonly tally: string;
    readonly decryptionParticipantIndices: readonly number[];
};

/**
 * Union of all unsigned protocol payload shapes that may appear on the board.
 */
export type ProtocolPayload =
    | ManifestPublicationPayload
    | RegistrationPayload
    | ManifestAcceptancePayload
    | PhaseCheckpointPayload
    | PedersenCommitmentPayload
    | EncryptedDualSharePayload
    | ComplaintPayload
    | ComplaintResolutionPayload
    | FeldmanCommitmentPayload
    | KeyDerivationConfirmation
    | BallotSubmissionPayload
    | BallotClosePayload
    | DecryptionSharePayload
    | TallyPublicationPayload;

/**
 * Unsigned protocol payload paired with an authentication signature.
 *
 * This is the canonical board record shape accepted by the audit and
 * verification layers.
 */
export type SignedPayload<TPayload extends ProtocolPayload = ProtocolPayload> =
    {
        readonly payload: TPayload;
        /** Raw Ed25519 signature bytes encoded as lowercase hex. */
        readonly signature: string;
    };

/**
 * Canonical election-manifest shape bound into protocol transcripts.
 *
 * The manifest is intentionally minimal and leaves threshold derivation to the
 * accepted registration roster.
 */
export type ElectionManifest = {
    readonly rosterHash: string;
    readonly optionList: readonly string[];
};

/**
 * Input bundle for verifying typed ballot payloads.
 */
type VerifyBallotSubmissionPayloadsInput = {
    readonly ballotPayloads: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly publicKey: EncodedPoint;
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
};

/** Input bundle for verifying typed ballot payloads across all options. */
export type VerifyBallotSubmissionPayloadsByOptionInput =
    VerifyBallotSubmissionPayloadsInput;

/**
 * Verified typed decryption-share payload.
 *
 * This pairs the original signed payload with the decoded low-level share used
 * in final tally recomputation.
 */
export type VerifiedDecryptionSharePayload = {
    readonly payload: SignedPayload<DecryptionSharePayload>;
    readonly share: DecryptionShare;
};

/** Verified aggregate input for one option slot. */
export type OptionAggregateInput = {
    readonly optionIndex: number;
    readonly aggregate: import('./voting-ballot-aggregation').VerifiedBallotAggregation['aggregate'];
};

/** Verified decryption shares grouped by option slot. */
export type VerifiedOptionDecryptionShares = {
    readonly optionIndex: number;
    readonly decryptionShares: readonly VerifiedDecryptionSharePayload[];
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
 * Input bundle for full ceremony verification across all published options.
 *
 * This is the top-level verifier input that an auditor or bulletin-board
 * reader supplies when replaying a full ceremony.
 */
export type VerifyElectionCeremonyInput = {
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
    readonly dkgTranscript: readonly SignedPayload[];
    readonly ballotPayloads: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly ballotClosePayload: SignedPayload<BallotClosePayload>;
    readonly decryptionSharePayloads: readonly SignedPayload<DecryptionSharePayload>[];
    readonly tallyPublications?: readonly SignedPayload<TallyPublicationPayload>[];
};

/**
 * Verified published tally for one option slot.
 *
 * The full ceremony verifier returns one of these per manifest option after
 * replaying ballots, decryption shares, and optional tally publications.
 */
export type VerifiedPublishedOptionVotingResult = {
    readonly optionIndex: number;
    readonly ballots: import('./voting-ballot-aggregation').VerifiedOptionBallotAggregation;
    readonly decryptionShares: readonly VerifiedDecryptionSharePayload[];
    readonly tally: bigint;
};
