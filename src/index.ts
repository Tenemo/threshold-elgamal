/**
 * Workflow-facing root package exports for the public API.
 *
 * Use this entry point for the supported voting workflow: manifest and roster
 * setup, transport keys and envelopes, standard signed protocol payload
 * builders, and the full ceremony verifier.
 *
 * Lower-level math, proof, threshold, DKG, VSS, and protocol primitives are
 * available through the public subpath modules such as
 * `threshold-elgamal/proofs`, `threshold-elgamal/threshold`, and
 * `threshold-elgamal/dkg`.
 *
 * @module threshold-elgamal
 * @packageDocumentation
 */
export { majorityThreshold } from './core/validation';

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
    EncryptedDualSharePayload,
    FeldmanCommitmentPayload,
    KeyDerivationConfirmation,
    ManifestAcceptancePayload,
    ManifestPublicationPayload,
    PedersenCommitmentPayload,
    PhaseCheckpointPayload,
    RegistrationPayload,
    SignedPayload,
    TallyPublicationPayload,
    VerifyElectionCeremonyInput,
} from './protocol/types';
