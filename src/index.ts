/**
 * Root package exports for the supported public API.
 *
 * Use this entry point for the full supported voting workflow: manifest and
 * roster setup, transport keys and envelopes, DKG commitments and share
 * handling, ballot encryption and proofs, decryption-share publication, tally
 * reconstruction, and full ceremony verification.
 *
 * Public subpath modules such as `threshold-elgamal/proofs`,
 * `threshold-elgamal/threshold`, and `threshold-elgamal/dkg` remain available
 * when you prefer grouped imports by subsystem, but the supported ceremony can
 * be implemented from this root package alone.
 *
 * @module threshold-elgamal
 * @packageDocumentation
 */
export { RISTRETTO_GROUP, modQ } from './core/public';
export type { EncodedPoint } from './core/public';
export { majorityThreshold } from './core/validation';

export { encryptAdditiveWithRandomness } from './elgamal/public';
export type { ElGamalCiphertext } from './elgamal/public';

export {
    deriveJointPublicKey,
    deriveTranscriptVerificationKey,
    encodePedersenShareEnvelope,
    decodePedersenShareEnvelope,
    verifyDKGTranscript,
} from './dkg/public';
export type {
    VerifyDKGTranscriptInput,
    VerifiedDKGTranscript,
} from './dkg/public';

export {
    createDisjunctiveProof,
    createDLEQProof,
    createSchnorrProof,
    verifyDisjunctiveProof,
    verifyDLEQProof,
    verifySchnorrProof,
} from './proofs/public';
export type {
    DLEQProof,
    DisjunctiveProof,
    DLEQStatement,
    ProofContext,
    SchnorrProof,
} from './proofs/public';

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
    signProtocolPayload,
    createTallyPublicationPayload,
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
export { verifyBallotSubmissionPayloadsByOption } from './protocol/voting-ballots';
export { scoreVotingDomain } from './protocol/voting-codecs';
export {
    verifyElectionCeremony,
    tryVerifyElectionCeremony,
    type ElectionVerificationErrorCode,
    type ElectionVerificationFailure,
    type ElectionVerificationResult,
    type ElectionVerificationStage,
    type VerifiedElectionCeremony,
} from './protocol/voting-verification';
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

export {
    combineDecryptionShares,
    createDecryptionShare,
    prepareAggregateForDecryption,
} from './threshold/public';
export type {
    AggregateDecryptionPreparationInput,
    DecryptionShare,
    Share,
    VerifiedAggregateCiphertext,
} from './threshold/public';

export {
    derivePedersenShares,
    generateFeldmanCommitments,
    generatePedersenCommitments,
    verifyFeldmanShare,
    verifyPedersenShare,
} from './vss/public';
export type {
    FeldmanCommitments,
    PedersenCommitments,
    PedersenShare,
} from './vss/public';
