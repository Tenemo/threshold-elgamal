export {
    IndexOutOfRangeError,
    InvalidGroupElementError,
    InvalidPayloadError,
    InvalidProofError,
    InvalidScalarError,
    InvalidShareError,
    PhaseViolationError,
    PlaintextDomainError,
    ThresholdViolationError,
    TranscriptMismatchError,
    UnsupportedSuiteError,
} from './core/errors.js';
export { modQ } from './core/bigint.js';
export { RISTRETTO_GROUP } from './core/groups.js';
export type { EncodedPoint } from './core/types.js';
export { majorityThreshold } from './core/validation.js';

export { encryptAdditiveWithRandomness } from './elgamal/additive.js';

export {
    createDisjunctiveProof,
    verifyDisjunctiveProof,
} from './proofs/disjunctive.js';
export {
    createDLEQProof,
    type DLEQStatement,
    verifyDLEQProof,
} from './proofs/dleq.js';
export { createSchnorrProof, verifySchnorrProof } from './proofs/schnorr.js';
export type {
    DLEQProof,
    DisjunctiveProof,
    ProofContext,
    SchnorrProof,
} from './proofs/types.js';

export { decryptEnvelope, encryptEnvelope } from './transport/envelopes.js';
export { exportAuthPublicKey, generateAuthKeyPair } from './transport/auth.js';
export {
    exportTransportPublicKey,
    generateTransportKeyPair,
} from './transport/key-agreement.js';
export type {
    EncodedAuthPublicKey,
    EncodedTransportPublicKey,
    EncryptedEnvelope,
    EnvelopeContext,
    KeyAgreementSuite,
    TransportKeyPair,
} from './transport/types.js';

export {
    combineDecryptionShares,
    createVerifiedDecryptionShare,
} from './threshold/decrypt.js';
export type {
    DecryptionShare,
    Share,
    VerifiedAggregateCiphertext,
} from './threshold/types.js';

export {
    deriveJointPublicKey,
    deriveTranscriptVerificationKey,
    verifyDKGTranscript,
} from './dkg/verification.js';
export {
    decodePedersenShareEnvelope,
    encodePedersenShareEnvelope,
} from './dkg/pedersen-share-codec.js';
export type {
    VerifyDKGTranscriptInput,
    VerifiedDKGTranscript,
} from './dkg/verification-types.js';

export {
    generateFeldmanCommitments,
    verifyFeldmanShare,
} from './vss/feldman.js';
export {
    derivePedersenShares,
    generatePedersenCommitments,
    verifyPedersenShare,
} from './vss/pedersen.js';
export type {
    FeldmanCommitments,
    PedersenCommitments,
    PedersenShare,
} from './vss/types.js';

export {
    createBallotClosePayload,
    createBallotSubmissionPayload,
    createDecryptionSharePayload,
    createEncryptedDualSharePayload,
    createFeldmanCommitmentPayload,
    createKeyDerivationConfirmationPayload,
    createManifestAcceptancePayload,
    createManifestPublicationPayload,
    createPedersenCommitmentPayload,
    createPhaseCheckpointPayload,
    createRegistrationPayload,
    createTallyPublicationPayload,
    signProtocolPayload,
} from './protocol/builders.js';
export {
    canonicalizeElectionManifest,
    createElectionManifest,
    deriveSessionId,
    hashElectionManifest,
    SHIPPED_PROTOCOL_VERSION,
    validateElectionManifest,
} from './protocol/manifest.js';
export { hashRosterEntries } from './protocol/verification.js';
export { hashProtocolTranscript } from './protocol/transcript.js';
export {
    verifyElectionCeremonyDetailed,
    verifyElectionCeremonyDetailedResult,
    type ElectionVerificationErrorCode,
    type ElectionVerificationFailure,
    type ElectionVerificationResult,
    type ElectionVerificationStage,
    type VerifiedElectionCeremonyDetailed,
    type VerifyElectionCeremonyDetailedInput,
} from './protocol/election-verification.js';
export { verifyBallotSubmissionPayloadsByOption } from './protocol/voting-ballots.js';
export { scoreVotingDomain } from './protocol/voting-codecs.js';
export type {
    BallotClosePayload,
    BallotSubmissionPayload,
    DecryptionSharePayload,
    ElectionManifest,
    EncodedCiphertext,
    EncodedCompactProof,
    EncodedDisjunctiveProof,
    EncryptedDualSharePayload,
    FeldmanCommitmentPayload,
    KeyDerivationConfirmation,
    ManifestAcceptancePayload,
    ManifestPublicationPayload,
    PedersenCommitmentPayload,
    PhaseCheckpointPayload,
    ProtocolMessageType,
    ProtocolPayload,
    RegistrationPayload,
    SignedPayload,
    TallyPublicationPayload,
} from './protocol/types.js';
