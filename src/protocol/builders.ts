import { encodeScalar } from '../core/ristretto.js';
import type { ElGamalCiphertext } from '../elgamal/types.js';
import type { DLEQProof, DisjunctiveProof } from '../proofs/types.js';
import { signPayloadBytes } from '../transport/auth.js';
import type {
    EncodedAuthPublicKey,
    EncodedTransportPublicKey,
} from '../transport/types.js';

import { canonicalUnsignedPayloadBytes } from './payloads.js';
import { hashProtocolPhaseSnapshot } from './transcript.js';
import type {
    BallotClosePayload,
    BallotSubmissionPayload,
    DecryptionSharePayload,
    ElectionManifest,
    EncodedCompactProof,
    EncryptedDualSharePayload,
    FeldmanCommitmentPayload,
    KeyDerivationConfirmation,
    ManifestAcceptancePayload,
    ManifestPublicationPayload,
    PedersenCommitmentPayload,
    PhaseCheckpointPayload,
    ProtocolPayload,
    RegistrationPayload,
    SignedPayload,
    TallyPublicationPayload,
} from './types.js';
import {
    encodeCiphertext,
    encodeCompactProof,
    encodeDisjunctiveProof,
} from './voting-codecs.js';
import {
    assertUniqueSortedIndices,
    BALLOT_CLOSE_PHASE,
    BALLOT_SUBMISSION_PHASE,
    DECRYPTION_SHARE_PHASE,
    TALLY_PUBLICATION_PHASE,
} from './voting-shared.js';

const isEncodedDisjunctiveProof = (
    proof: BallotSubmissionPayload['proof'] | DisjunctiveProof,
): proof is BallotSubmissionPayload['proof'] =>
    typeof proof.branches[0]?.challenge === 'string';

const isEncodedCompactProof = (
    proof: DecryptionSharePayload['proof'] | DLEQProof,
): proof is DecryptionSharePayload['proof'] =>
    typeof proof.challenge === 'string';

const isEncodedFeldmanProofEntry = (
    proof:
        | FeldmanCommitmentPayload['proofs'][number]
        | {
              readonly coefficientIndex: number;
              readonly challenge: bigint;
              readonly response: bigint;
          },
): proof is FeldmanCommitmentPayload['proofs'][number] =>
    typeof proof.challenge === 'string';

/** Signs one canonical protocol payload with a participant auth key. */
export const signProtocolPayload = async <TPayload extends ProtocolPayload>(
    privateKey: CryptoKey,
    payload: TPayload,
): Promise<SignedPayload<TPayload>> => ({
    payload,
    signature: await signPayloadBytes(
        privateKey,
        canonicalUnsignedPayloadBytes(payload),
    ),
});

/** Creates a signed manifest-publication payload. */
export const createManifestPublicationPayload = async (
    privateKey: CryptoKey,
    input: {
        readonly manifest: ElectionManifest;
        readonly manifestHash: string;
        readonly participantIndex: number;
        readonly sessionId: string;
    },
): Promise<SignedPayload<ManifestPublicationPayload>> =>
    signProtocolPayload(privateKey, {
        sessionId: input.sessionId,
        manifestHash: input.manifestHash,
        phase: 0,
        participantIndex: input.participantIndex,
        messageType: 'manifest-publication',
        manifest: input.manifest,
    });

/** Creates a signed registration payload for one participant. */
export const createRegistrationPayload = async (
    privateKey: CryptoKey,
    input: {
        readonly authPublicKey: EncodedAuthPublicKey;
        readonly manifestHash: string;
        readonly participantIndex: number;
        readonly rosterHash: string;
        readonly sessionId: string;
        readonly transportPublicKey: EncodedTransportPublicKey;
    },
): Promise<SignedPayload<RegistrationPayload>> =>
    signProtocolPayload(privateKey, {
        sessionId: input.sessionId,
        manifestHash: input.manifestHash,
        phase: 0,
        participantIndex: input.participantIndex,
        messageType: 'registration',
        rosterHash: input.rosterHash,
        authPublicKey: input.authPublicKey,
        transportPublicKey: input.transportPublicKey,
    });

/** Creates a signed manifest-acceptance payload. */
export const createManifestAcceptancePayload = async (
    privateKey: CryptoKey,
    input: {
        readonly accountIdHash?: string;
        readonly assignedParticipantIndex: number;
        readonly manifestHash: string;
        readonly participantIndex: number;
        readonly rosterHash: string;
        readonly sessionId: string;
    },
): Promise<SignedPayload<ManifestAcceptancePayload>> =>
    signProtocolPayload(privateKey, {
        sessionId: input.sessionId,
        manifestHash: input.manifestHash,
        phase: 0,
        participantIndex: input.participantIndex,
        messageType: 'manifest-acceptance',
        rosterHash: input.rosterHash,
        assignedParticipantIndex: input.assignedParticipantIndex,
        ...(input.accountIdHash === undefined
            ? {}
            : {
                  accountIdHash: input.accountIdHash,
              }),
    });

/** Creates a signed phase-checkpoint payload over one DKG phase snapshot. */
export const createPhaseCheckpointPayload = async (
    privateKey: CryptoKey,
    input: {
        readonly checkpointPhase: 0 | 1 | 2 | 3;
        readonly manifestHash: string;
        readonly participantIndex: number;
        readonly qualParticipantIndices: readonly number[];
        readonly sessionId: string;
        readonly transcript: readonly SignedPayload[];
    },
): Promise<SignedPayload<PhaseCheckpointPayload>> =>
    signProtocolPayload(privateKey, {
        sessionId: input.sessionId,
        manifestHash: input.manifestHash,
        phase: input.checkpointPhase,
        participantIndex: input.participantIndex,
        messageType: 'phase-checkpoint',
        checkpointPhase: input.checkpointPhase,
        checkpointTranscriptHash: await hashProtocolPhaseSnapshot(
            input.transcript.map((entry) => entry.payload),
            input.checkpointPhase,
        ),
        qualParticipantIndices: [...input.qualParticipantIndices],
    });

/** Creates a signed Pedersen-commitment payload for DKG phase 1. */
export const createPedersenCommitmentPayload = async (
    privateKey: CryptoKey,
    input: Omit<PedersenCommitmentPayload, 'messageType' | 'phase'>,
): Promise<SignedPayload<PedersenCommitmentPayload>> =>
    signProtocolPayload(privateKey, {
        ...input,
        phase: 1,
        messageType: 'pedersen-commitment',
        commitments: [...input.commitments],
    });

/** Creates a signed encrypted dual-share payload for DKG phase 1. */
export const createEncryptedDualSharePayload = async (
    privateKey: CryptoKey,
    input: Omit<EncryptedDualSharePayload, 'messageType' | 'phase'>,
): Promise<SignedPayload<EncryptedDualSharePayload>> =>
    signProtocolPayload(privateKey, {
        ...input,
        phase: 1,
        messageType: 'encrypted-dual-share',
    });

/** Creates a signed Feldman-commitment payload for DKG phase 3. */
export const createFeldmanCommitmentPayload = async (
    privateKey: CryptoKey,
    input: Omit<
        FeldmanCommitmentPayload,
        'messageType' | 'phase' | 'proofs'
    > & {
        readonly proofs:
            | FeldmanCommitmentPayload['proofs']
            | readonly (
                  | {
                        readonly coefficientIndex: number;
                        readonly challenge: bigint;
                        readonly response: bigint;
                    }
                  | ({
                        readonly coefficientIndex: number;
                    } & EncodedCompactProof)
              )[];
    },
): Promise<SignedPayload<FeldmanCommitmentPayload>> => {
    const payload: FeldmanCommitmentPayload = {
        ...input,
        phase: 3,
        messageType: 'feldman-commitment',
        commitments: [...input.commitments],
        proofs: input.proofs.map((proof) => ({
            coefficientIndex: proof.coefficientIndex,
            ...(isEncodedFeldmanProofEntry(proof)
                ? {
                      challenge: proof.challenge,
                      response: proof.response,
                  }
                : encodeCompactProof(proof)),
        })),
    };

    return signProtocolPayload(privateKey, payload);
};

/** Creates a signed key-derivation-confirmation payload for DKG phase 4. */
export const createKeyDerivationConfirmationPayload = async (
    privateKey: CryptoKey,
    input: Omit<KeyDerivationConfirmation, 'messageType' | 'phase'>,
): Promise<SignedPayload<KeyDerivationConfirmation>> =>
    signProtocolPayload(privateKey, {
        ...input,
        phase: 4,
        messageType: 'key-derivation-confirmation',
    });

/** Creates a signed ballot payload for one participant and one option slot. */
export const createBallotSubmissionPayload = async (
    privateKey: CryptoKey,
    input: Omit<
        BallotSubmissionPayload,
        'messageType' | 'phase' | 'ciphertext' | 'proof'
    > & {
        readonly ciphertext:
            | BallotSubmissionPayload['ciphertext']
            | ElGamalCiphertext;
        readonly proof: BallotSubmissionPayload['proof'] | DisjunctiveProof;
    },
): Promise<SignedPayload<BallotSubmissionPayload>> => {
    const payload: BallotSubmissionPayload = {
        ...input,
        phase: BALLOT_SUBMISSION_PHASE,
        messageType: 'ballot-submission',
        ciphertext: encodeCiphertext(input.ciphertext as ElGamalCiphertext),
        proof: isEncodedDisjunctiveProof(input.proof)
            ? input.proof
            : encodeDisjunctiveProof(input.proof),
    };

    return signProtocolPayload(privateKey, payload);
};

/** Creates the organizer-signed ballot cutoff payload. */
export const createBallotClosePayload = async (
    privateKey: CryptoKey,
    input: Omit<BallotClosePayload, 'messageType' | 'phase'>,
): Promise<SignedPayload<BallotClosePayload>> => {
    const includedParticipantIndices = [
        ...input.includedParticipantIndices,
    ].sort((left, right) => left - right);
    assertUniqueSortedIndices(
        includedParticipantIndices,
        'Ballot close participant',
    );

    return signProtocolPayload(privateKey, {
        ...input,
        phase: BALLOT_CLOSE_PHASE,
        messageType: 'ballot-close',
        includedParticipantIndices,
    });
};

/** Creates a signed threshold decryption-share payload for one option slot. */
export const createDecryptionSharePayload = async (
    privateKey: CryptoKey,
    input: Omit<DecryptionSharePayload, 'messageType' | 'phase' | 'proof'> & {
        readonly proof: DecryptionSharePayload['proof'] | DLEQProof;
    },
): Promise<SignedPayload<DecryptionSharePayload>> => {
    const payload: DecryptionSharePayload = {
        ...input,
        phase: DECRYPTION_SHARE_PHASE,
        messageType: 'decryption-share',
        proof: isEncodedCompactProof(input.proof)
            ? input.proof
            : encodeCompactProof(input.proof),
    };

    return signProtocolPayload(privateKey, payload);
};

/** Creates a signed tally-publication payload for one option slot. */
export const createTallyPublicationPayload = async (
    privateKey: CryptoKey,
    input: Omit<TallyPublicationPayload, 'messageType' | 'phase' | 'tally'> & {
        readonly tally: TallyPublicationPayload['tally'] | bigint;
    },
): Promise<SignedPayload<TallyPublicationPayload>> => {
    const decryptionParticipantIndices = [
        ...input.decryptionParticipantIndices,
    ].sort((left, right) => left - right);
    assertUniqueSortedIndices(
        decryptionParticipantIndices,
        'Decryption participant',
    );

    return signProtocolPayload(privateKey, {
        ...input,
        phase: TALLY_PUBLICATION_PHASE,
        messageType: 'tally-publication',
        decryptionParticipantIndices,
        tally:
            typeof input.tally === 'bigint'
                ? encodeScalar(input.tally)
                : input.tally,
    });
};
