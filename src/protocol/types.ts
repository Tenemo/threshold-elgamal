import type { EncodedPoint } from '../core/types.js';
import type {
    EncodedAuthPublicKey,
    EncodedTransportPrivateKey,
    EncodedTransportPublicKey,
} from '../transport/types.js';

/** Canonical protocol payload type identifiers. */
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

/** Shared fields present on every unsigned protocol payload. */
export type BaseProtocolPayload = {
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

/** Registration payload carrying ceremony auth and transport keys. */
export type RegistrationPayload = BaseProtocolPayload & {
    readonly messageType: 'registration';
    readonly rosterHash: string;
    readonly authPublicKey: EncodedAuthPublicKey;
    readonly transportPublicKey: EncodedTransportPublicKey;
};

/** Participant-signed manifest acceptance payload. */
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
    readonly qualParticipantIndices: readonly number[];
};

/** Broadcast payload carrying Pedersen coefficient commitments. */
export type PedersenCommitmentPayload = BaseProtocolPayload & {
    readonly messageType: 'pedersen-commitment';
    readonly commitments: readonly string[];
};

/** Encrypted share-envelope payload for the share-distribution step. */
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

/** Broadcast payload carrying Feldman commitments and coefficient proofs. */
export type FeldmanCommitmentPayload = BaseProtocolPayload & {
    readonly messageType: 'feldman-commitment';
    readonly commitments: readonly string[];
    readonly proofs: readonly {
        readonly coefficientIndex: number;
        readonly challenge: string;
        readonly response: string;
    }[];
};

/** Optional final key-derivation confirmation payload for the derived joint key. */
export type KeyDerivationConfirmation = BaseProtocolPayload & {
    readonly messageType: 'key-derivation-confirmation';
    readonly qualHash: string;
    readonly publicKey: EncodedPoint;
};

/** Signed manifest-publication payload anchoring the frozen manifest. */
export type ManifestPublicationPayload = BaseProtocolPayload & {
    readonly messageType: 'manifest-publication';
    readonly manifest: ElectionManifest;
};

/** Signed additive ballot payload for one participant and one option slot. */
export type BallotSubmissionPayload = BaseProtocolPayload & {
    readonly messageType: 'ballot-submission';
    readonly optionIndex: number;
    readonly ciphertext: EncodedCiphertext;
    readonly proof: EncodedDisjunctiveProof;
};

/** Signed organizer payload that freezes which participants are counted. */
export type BallotClosePayload = BaseProtocolPayload & {
    readonly messageType: 'ballot-close';
    readonly includedParticipantIndices: readonly number[];
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

/** Signed tally-publication payload for the recovered additive tally. */
export type TallyPublicationPayload = BaseProtocolPayload & {
    readonly messageType: 'tally-publication';
    readonly optionIndex: number;
    readonly transcriptHash: string;
    readonly ballotCount: number;
    readonly tally: string;
    readonly decryptionParticipantIndices: readonly number[];
};

/** Union of all unsigned protocol payload shapes. */
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

/** Unsigned protocol payload paired with an authentication signature. */
export type SignedPayload<TPayload extends ProtocolPayload = ProtocolPayload> =
    {
        readonly payload: TPayload;
        /** Raw Ed25519 signature bytes encoded as lowercase hex. */
        readonly signature: string;
    };

/** Canonical election-manifest shape bound into protocol transcripts. */
export type ElectionManifest = {
    readonly rosterHash: string;
    readonly optionList: readonly string[];
};
