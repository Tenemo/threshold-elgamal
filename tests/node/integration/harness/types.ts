import type { CryptoGroup, GroupName } from '#core';
import type { DKGState } from '#dkg';
import type { DLEQProof, DisjunctiveProof, ProofContext } from '#proofs';
import type {
    BallotSubmissionPayload,
    DecryptionSharePayload,
    ElectionManifest,
    EncryptedDualSharePayload,
    FeldmanCommitmentPayload,
    PedersenCommitmentPayload,
    RegistrationPayload,
    SignedPayload,
    TallyPublicationPayload,
} from '#protocol';
import type { DecryptionShare, Share } from '#threshold';
import type {
    ComplaintResolution,
    EncryptedEnvelope,
    KeyAgreementSuite,
} from '#transport';
import type { PedersenShare } from '#vss';

export type ParticipantRuntime = {
    readonly auth: CryptoKeyPair;
    readonly authPublicKeyHex: string;
    readonly index: number;
    readonly transportPrivateKey: CryptoKey;
    readonly transportPublicKeyHex: string;
    readonly transportSuite: KeyAgreementSuite;
};

export type EnvelopeArtifact = {
    readonly envelope: EncryptedEnvelope;
    readonly ephemeralPrivateKey: string;
    readonly recipientIndex: number;
    readonly share: PedersenShare;
    readonly signedPayload: SignedPayload<EncryptedDualSharePayload>;
};

export type DealerMaterial = {
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
    readonly envelopeTamper?: 'ciphertext' | 'ephemeralPublicKey' | 'iv';
    readonly reason?:
        | 'aes-gcm-failure'
        | 'malformed-plaintext'
        | 'pedersen-failure';
    readonly recipientIndex: number;
    readonly resolutionOutcome?: 'dealer-fault' | 'complainant-fault';
};

export type VotingFlowScenario = {
    readonly allowAbstention?: boolean;
    readonly complaints?: readonly ComplaintInjection[];
    readonly decryptionParticipantIndices?: readonly number[];
    readonly group?: GroupName;
    readonly participantCount: number;
    readonly scoreDomainMax?: number;
    readonly threshold?: number;
    readonly transportSuite?: KeyAgreementSuite;
    readonly votes: readonly bigint[];
};

export type BallotArtifact = {
    readonly ciphertext: { readonly c1: bigint; readonly c2: bigint };
    readonly proof: DisjunctiveProof;
    readonly proofContext: ProofContext;
    readonly vote: bigint;
    readonly voterIndex: number;
};

export type ThresholdShareArtifact = {
    readonly proof: DLEQProof;
    readonly share: DecryptionShare;
};

type CommonScenarioResult = {
    readonly aggregate: { readonly c1: bigint; readonly c2: bigint };
    readonly ballotLogHash?: string;
    readonly ballotPayloads?: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly ballots: readonly BallotArtifact[];
    readonly complaintResolutions: readonly (ComplaintResolution & {
        readonly dealerIndex: number;
        readonly recipientIndex: number;
    })[];
    readonly decryptionSharePayloads?: readonly SignedPayload<DecryptionSharePayload>[];
    readonly dkgTranscript: readonly SignedPayload[];
    readonly directJointSecret?: bigint;
    readonly finalShares?: readonly Share[];
    readonly finalState: DKGState;
    readonly group: CryptoGroup;
    readonly jointPublicKey?: bigint;
    readonly manifest: ElectionManifest;
    readonly manifestHash: string;
    readonly mismatchedAggregate?: {
        readonly c1: bigint;
        readonly c2: bigint;
    };
    readonly participantAuthKeys: readonly {
        readonly index: number;
        readonly privateKey: CryptoKey;
    }[];
    readonly registrations: readonly SignedPayload<RegistrationPayload>[];
    readonly sessionFingerprint: string;
    readonly sessionId: string;
    readonly tallyPublication?: SignedPayload<TallyPublicationPayload>;
    readonly thresholdShareArtifacts?: readonly ThresholdShareArtifact[];
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
