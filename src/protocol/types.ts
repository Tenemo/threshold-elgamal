import type { GroupName } from '../core/types.js';

/** Canonical protocol payload type identifiers. */
export type ProtocolMessageType =
    | 'manifest-publication'
    | 'registration'
    | 'manifest-acceptance'
    | 'pedersen-commitment'
    | 'encrypted-dual-share'
    | 'complaint'
    | 'complaint-resolution'
    | 'feldman-commitment'
    | 'feldman-share-reveal'
    | 'key-derivation-confirmation'
    | 'ballot-submission'
    | 'decryption-share'
    | 'tally-publication'
    | 'ceremony-restart';

/** Complaint reasons recognized by the protocol layer. */
export type ComplaintReason =
    | 'aes-gcm-failure'
    | 'malformed-plaintext'
    | 'pedersen-failure';

/** Public restart reason codes for aborted ceremonies. */
export type RestartReasonCode =
    | 'qual-too-small'
    | 'timeout'
    | 'equivocation-detected'
    | 'local-aggregate-mismatch';

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
    readonly authPublicKey: string;
    readonly transportPublicKey: string;
};

/** Participant-signed manifest acceptance payload. */
export type ManifestAcceptancePayload = BaseProtocolPayload & {
    readonly messageType: 'manifest-acceptance';
    readonly rosterHash: string;
    readonly assignedParticipantIndex: number;
    readonly accountIdHash?: string;
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
    readonly suite: 'X25519' | 'P-256';
    readonly ephemeralPublicKey: string;
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
    readonly suite: 'X25519' | 'P-256';
    readonly revealedEphemeralPrivateKey: string;
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

/** Public share-reveal payload used for complaint-driven reconstruction. */
export type FeldmanShareRevealPayload = BaseProtocolPayload & {
    readonly messageType: 'feldman-share-reveal';
    readonly dealerIndex: number;
    readonly shareValue: string;
};

/** Final key-derivation confirmation payload. */
export type KeyDerivationConfirmation = BaseProtocolPayload & {
    readonly messageType: 'key-derivation-confirmation';
    readonly qualHash: string;
    readonly publicKey: string;
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

/**
 * Signed threshold decryption-share payload tied to a locally recomputed
 * additive aggregate transcript.
 */
export type DecryptionSharePayload = BaseProtocolPayload & {
    readonly messageType: 'decryption-share';
    readonly transcriptHash: string;
    readonly ballotCount: number;
    readonly decryptionShare: string;
    readonly proof: EncodedCompactProof;
};

/** Signed tally-publication payload for the recovered additive tally. */
export type TallyPublicationPayload = BaseProtocolPayload & {
    readonly messageType: 'tally-publication';
    readonly transcriptHash: string;
    readonly ballotCount: number;
    readonly tally: string;
    readonly decryptionParticipantIndices: readonly number[];
};

/** Signed link from a restarted ceremony to the aborted prior attempt. */
export type CeremonyRestartPayload = BaseProtocolPayload & {
    readonly messageType: 'ceremony-restart';
    readonly previousSessionId: string;
    readonly previousTranscriptHash: string;
    readonly reason: RestartReasonCode;
};

/** Union of all unsigned protocol payload shapes. */
export type ProtocolPayload =
    | ManifestPublicationPayload
    | RegistrationPayload
    | ManifestAcceptancePayload
    | PedersenCommitmentPayload
    | EncryptedDualSharePayload
    | ComplaintPayload
    | ComplaintResolutionPayload
    | FeldmanCommitmentPayload
    | FeldmanShareRevealPayload
    | KeyDerivationConfirmation
    | BallotSubmissionPayload
    | DecryptionSharePayload
    | TallyPublicationPayload
    | CeremonyRestartPayload;

/** Unsigned protocol payload paired with an authentication signature. */
export type SignedPayload<TPayload extends ProtocolPayload = ProtocolPayload> =
    {
        readonly payload: TPayload;
        /** Raw IEEE P1363 signature bytes encoded as lowercase hex. */
        readonly signature: string;
    };

/** Canonical election-manifest shape bound into protocol transcripts. */
export type ElectionManifest = {
    readonly protocolVersion: string;
    readonly suiteId: GroupName;
    readonly threshold: number;
    readonly participantCount: number;
    readonly minimumPublicationThreshold: number;
    readonly allowAbstention: boolean;
    readonly scoreDomainMin: number;
    readonly scoreDomainMax: number;
    readonly ballotFinality: 'first-valid';
    readonly rosterHash: string;
    readonly optionList: readonly string[];
    readonly epochDeadlines: readonly string[];
};
