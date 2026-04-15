/**
 * Safe root package exports for the public API.
 *
 * Use this entry point for group definitions, additive ElGamal, validation
 * helpers, protocol helpers, transport helpers, and serialization helpers.
 *
 * @module threshold-elgamal
 * @packageDocumentation
 */
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
} from './core/errors';
export { modQ } from './core/bigint';
export { RISTRETTO_GROUP } from './core/groups';
export type { EncodedPoint } from './core/types';
export { majorityThreshold } from './core/validation';

export { encryptAdditiveWithRandomness } from './elgamal/additive';

export {
    createDisjunctiveProof,
    verifyDisjunctiveProof,
} from './proofs/disjunctive';
export {
    createDLEQProof,
    type DLEQStatement,
    verifyDLEQProof,
} from './proofs/dleq';
export { createSchnorrProof, verifySchnorrProof } from './proofs/schnorr';
export type {
    DLEQProof,
    DisjunctiveProof,
    ProofContext,
    SchnorrProof,
} from './proofs/types';

export { decryptEnvelope, encryptEnvelope } from './transport/envelopes';
export { exportAuthPublicKey, generateAuthKeyPair } from './transport/auth';
export {
    exportTransportPublicKey,
    generateTransportKeyPair,
} from './transport/key-agreement';
export type {
    EncodedAuthPublicKey,
    EncodedTransportPublicKey,
    EncryptedEnvelope,
    EnvelopeContext,
    TransportKeyPair,
} from './transport/types';

export {
    combineDecryptionShares,
    createDecryptionShare,
    prepareAggregateForDecryption,
} from './threshold/decrypt';
export type {
    AggregateDecryptionPreparationInput,
    DecryptionShare,
    Share,
    VerifiedAggregateCiphertext,
} from './threshold/types';

export {
    deriveJointPublicKey,
    deriveTranscriptVerificationKey,
    verifyDKGTranscript,
} from './dkg/verification';
export {
    decodePedersenShareEnvelope,
    encodePedersenShareEnvelope,
} from './dkg/pedersen-share-codec';
export type {
    VerifyDKGTranscriptInput,
    VerifiedDKGTranscript,
} from './dkg/verification';

export { generateFeldmanCommitments, verifyFeldmanShare } from './vss/feldman';
export {
    derivePedersenShares,
    generatePedersenCommitments,
    verifyPedersenShare,
} from './vss/pedersen';
export type {
    FeldmanCommitments,
    PedersenCommitments,
    PedersenShare,
} from './vss/types';

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
} from './protocol/builders';
export {
    canonicalizeElectionManifest,
    createElectionManifest,
    deriveSessionId,
    hashElectionManifest,
    SHIPPED_PROTOCOL_VERSION,
    validateElectionManifest,
} from './protocol/manifest';
export { hashRosterEntries } from './protocol/verification';
export { hashProtocolTranscript } from './protocol/transcript';
export {
    verifyElectionCeremony,
    tryVerifyElectionCeremony,
    type ElectionVerificationErrorCode,
    type ElectionVerificationFailure,
    type ElectionVerificationResult,
    type ElectionVerificationStage,
    type VerifiedElectionCeremony,
} from './protocol/voting-verification';
export { verifyBallotSubmissionPayloadsByOption } from './protocol/voting-ballots';
export { scoreVotingDomain } from './protocol/voting-codecs';
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
    VerifyElectionCeremonyInput,
} from './protocol/types';
