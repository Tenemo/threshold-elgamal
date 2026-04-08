import type { GroupName } from '../core/types.js';

/** Canonical protocol payload type identifiers. */
export type ProtocolMessageType =
    | 'registration'
    | 'manifest-acceptance'
    | 'pedersen-commitment'
    | 'encrypted-dual-share'
    | 'complaint'
    | 'feldman-commitment'
    | 'feldman-share-reveal'
    | 'key-derivation-confirmation';

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

/** Union of all unsigned protocol payload shapes. */
export type ProtocolPayload =
    | RegistrationPayload
    | ManifestAcceptancePayload
    | PedersenCommitmentPayload
    | EncryptedDualSharePayload
    | ComplaintPayload
    | FeldmanCommitmentPayload
    | FeldmanShareRevealPayload
    | KeyDerivationConfirmation;

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
