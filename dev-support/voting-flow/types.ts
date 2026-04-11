import type { CryptoGroup, EncodedPoint, GroupIdentifier } from '#core';
import type { DKGState } from '#dkg';
import type { ElgamalCiphertext } from '#elgamal';
import type { DLEQProof, DisjunctiveProof, ProofContext } from '#proofs';
import type {
    BallotClosePayload,
    BallotSubmissionPayload,
    DecryptionSharePayload,
    ElectionManifest,
    EncryptedDualSharePayload,
    FeldmanCommitmentPayload,
    PhaseCheckpointPayload,
    PedersenCommitmentPayload,
    RegistrationPayload,
    SignedPayload,
    TallyPublicationPayload,
} from '#protocol';
import type { DecryptionShare, Share } from '#threshold';
import type {
    EncodedAuthPublicKey,
    EncodedTransportPrivateKey,
    EncodedTransportPublicKey,
    ComplaintResolution,
    EncryptedEnvelope,
    KeyAgreementSuite,
} from '#transport';
import type { PedersenShare } from '#vss';

export type ParticipantRuntime = {
    readonly auth: CryptoKeyPair;
    readonly authPublicKeyHex: EncodedAuthPublicKey;
    readonly index: number;
    readonly transportPrivateKey: CryptoKey;
    readonly transportPublicKeyHex: EncodedTransportPublicKey;
    readonly transportSuite: KeyAgreementSuite;
};

export type EnvelopeArtifact = {
    readonly envelope: EncryptedEnvelope;
    readonly ephemeralPrivateKey: EncodedTransportPrivateKey;
    readonly recipientIndex: number;
    readonly share: PedersenShare;
    readonly signedPayload: SignedPayload<EncryptedDualSharePayload>;
};

export type DealerMaterial = {
    readonly encryptedShares: readonly EnvelopeArtifact[];
    readonly feldmanCommitmentPayload: SignedPayload<FeldmanCommitmentPayload>;
    readonly feldmanCommitments: readonly EncodedPoint[];
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
    readonly complaints?: readonly ComplaintInjection[];
    readonly decryptionParticipantIndices?: readonly number[];
    readonly group?: GroupIdentifier;
    readonly includeKeyDerivationConfirmations?: boolean;
    readonly missingEncryptedShareDealerIndices?: readonly number[];
    readonly missingFeldmanCommitmentParticipantIndices?: readonly number[];
    readonly missingKeyDerivationConfirmationParticipantIndices?: readonly number[];
    readonly missingPedersenCommitmentParticipantIndices?: readonly number[];
    readonly missingPhaseCheckpointSignerIndices?: Partial<
        Record<0 | 1 | 2 | 3, readonly number[]>
    >;
    readonly optionList?: readonly string[];
    readonly participantCount: number;
    readonly threshold?: number;
    readonly transportSuite?: KeyAgreementSuite;
    readonly votes: readonly bigint[];
    readonly votesByOption?: readonly (readonly bigint[])[];
};

export type BallotArtifact = {
    readonly ciphertext: ElgamalCiphertext;
    readonly proof: DisjunctiveProof;
    readonly proofContext: ProofContext;
    readonly vote: bigint;
    readonly voterIndex: number;
};

export type ThresholdShareArtifact = {
    readonly proof: DLEQProof;
    readonly share: DecryptionShare;
};

export type OptionVotingArtifacts = {
    readonly aggregate: ElgamalCiphertext;
    readonly ballotLogHash: string;
    readonly ballots: readonly BallotArtifact[];
    readonly expectedTally: bigint;
    readonly mismatchedAggregate: ElgamalCiphertext;
    readonly optionIndex: number;
    readonly recovered: bigint;
    readonly recoveredWithAllShares: bigint;
    readonly tallyPublication: SignedPayload<TallyPublicationPayload>;
    readonly thresholdShareArtifacts: readonly ThresholdShareArtifact[];
};

type CommonScenarioResult = {
    readonly aggregate: ElgamalCiphertext;
    readonly ballotLogHash?: string;
    readonly ballotClosePayload?: SignedPayload<BallotClosePayload>;
    readonly ballotPayloads?: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly ballots: readonly BallotArtifact[];
    readonly complaintResolutions: readonly (ComplaintResolution & {
        readonly dealerIndex: number;
        readonly recipientIndex: number;
    })[];
    readonly decryptionSharePayloads?: readonly SignedPayload<DecryptionSharePayload>[];
    readonly dkgTranscript: readonly SignedPayload[];
    readonly dkgPhaseCheckpoints?: readonly SignedPayload<PhaseCheckpointPayload>[];
    readonly directJointSecret?: bigint;
    readonly finalShares?: readonly Share[];
    readonly finalState: DKGState;
    readonly group: CryptoGroup;
    readonly jointPublicKey?: EncodedPoint;
    readonly manifest: ElectionManifest;
    readonly manifestHash: string;
    readonly mismatchedAggregate?: ElgamalCiphertext;
    readonly optionResults?: readonly OptionVotingArtifacts[];
    readonly participantAuthKeys: readonly {
        readonly index: number;
        readonly privateKey: CryptoKey;
    }[];
    readonly registrations: readonly SignedPayload<RegistrationPayload>[];
    readonly sessionFingerprint: string;
    readonly sessionId: string;
    readonly tallyPublication?: SignedPayload<TallyPublicationPayload>;
    readonly tallyPublications?: readonly SignedPayload<TallyPublicationPayload>[];
    readonly thresholdShareArtifacts?: readonly ThresholdShareArtifact[];
    readonly transcriptDerivedVerificationKeys?: readonly {
        readonly index: number;
        readonly value: EncodedPoint;
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
