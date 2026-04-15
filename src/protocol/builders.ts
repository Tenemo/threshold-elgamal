import { encodeScalar } from '../core/ristretto';
import type { ElGamalCiphertext } from '../elgamal/types';
import type { DLEQProof, DisjunctiveProof } from '../proofs/types';
import { signPayloadBytes } from '../transport/auth';
import type {
    EncodedAuthPublicKey,
    EncodedTransportPublicKey,
} from '../transport/types';

import type { ProtocolPayloadInput } from './payloads';
import { attachProtocolVersion, signedProtocolPayloadBytes } from './payloads';
import { hashProtocolPhaseSnapshot } from './transcript';
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
    ProtocolMessageType,
    ProtocolPayload,
    RegistrationPayload,
    SignedPayload,
    TallyPublicationPayload,
} from './types';
import {
    encodeCiphertext,
    encodeCompactProof,
    encodeDisjunctiveProof,
} from './voting-codecs';
import {
    assertUniqueSortedIndices,
    BALLOT_CLOSE_PHASE,
    BALLOT_SUBMISSION_PHASE,
    DECRYPTION_SHARE_PHASE,
    TALLY_PUBLICATION_PHASE,
} from './voting-shared';

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

type ProtocolPayloadByMessageType<TMessageType extends ProtocolMessageType> =
    Extract<ProtocolPayload, { readonly messageType: TMessageType }>;

/** Signs one canonical protocol payload with a participant auth key. */
export const signProtocolPayload = async <
    TMessageType extends ProtocolMessageType,
>(
    privateKey: CryptoKey,
    payload: ProtocolPayloadInput<
        ProtocolPayloadByMessageType<TMessageType>
    > & {
        readonly messageType: TMessageType;
    },
): Promise<SignedPayload<ProtocolPayloadByMessageType<TMessageType>>> => {
    const signedPayload = attachProtocolVersion(payload);

    return {
        payload: signedPayload,
        signature: await signPayloadBytes(
            privateKey,
            signedProtocolPayloadBytes(signedPayload),
        ),
    };
};

/** Creates a signed manifest-publication payload. */
export const createManifestPublicationPayload = async (
    privateKey: CryptoKey,
    input: {
        readonly manifest: ElectionManifest;
        readonly manifestHash: string;
        readonly participantIndex: number;
        readonly protocolVersion?: string;
        readonly sessionId: string;
    },
): Promise<SignedPayload<ManifestPublicationPayload>> =>
    signProtocolPayload(privateKey, {
        protocolVersion: input.protocolVersion,
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
        readonly protocolVersion?: string;
        readonly rosterHash: string;
        readonly sessionId: string;
        readonly transportPublicKey: EncodedTransportPublicKey;
    },
): Promise<SignedPayload<RegistrationPayload>> =>
    signProtocolPayload(privateKey, {
        protocolVersion: input.protocolVersion,
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
        readonly protocolVersion?: string;
        readonly rosterHash: string;
        readonly sessionId: string;
    },
): Promise<SignedPayload<ManifestAcceptancePayload>> =>
    signProtocolPayload(privateKey, {
        protocolVersion: input.protocolVersion,
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
        readonly protocolVersion?: string;
        readonly qualifiedParticipantIndices: readonly number[];
        readonly sessionId: string;
        readonly transcript: readonly SignedPayload[];
    },
): Promise<SignedPayload<PhaseCheckpointPayload>> =>
    signProtocolPayload(privateKey, {
        protocolVersion: input.protocolVersion,
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
        qualifiedParticipantIndices: [...input.qualifiedParticipantIndices],
    });

/** Creates a signed Pedersen-commitment payload for DKG phase 1. */
export const createPedersenCommitmentPayload = async (
    privateKey: CryptoKey,
    input: Omit<
        PedersenCommitmentPayload,
        'messageType' | 'phase' | 'protocolVersion'
    > & {
        readonly protocolVersion?: string;
    },
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
    input: Omit<
        EncryptedDualSharePayload,
        'messageType' | 'phase' | 'protocolVersion'
    > & {
        readonly protocolVersion?: string;
    },
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
        'messageType' | 'phase' | 'proofs' | 'protocolVersion'
    > & {
        readonly protocolVersion?: string;
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
    const payload: ProtocolPayloadInput<FeldmanCommitmentPayload> = {
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
    input: Omit<
        KeyDerivationConfirmation,
        'messageType' | 'phase' | 'protocolVersion'
    > & {
        readonly protocolVersion?: string;
    },
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
        'messageType' | 'phase' | 'ciphertext' | 'proof' | 'protocolVersion'
    > & {
        readonly protocolVersion?: string;
        readonly ciphertext:
            | BallotSubmissionPayload['ciphertext']
            | ElGamalCiphertext;
        readonly proof: BallotSubmissionPayload['proof'] | DisjunctiveProof;
    },
): Promise<SignedPayload<BallotSubmissionPayload>> => {
    const payload: ProtocolPayloadInput<BallotSubmissionPayload> = {
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
    input: Omit<
        BallotClosePayload,
        'messageType' | 'phase' | 'protocolVersion'
    > & {
        readonly protocolVersion?: string;
    },
): Promise<SignedPayload<BallotClosePayload>> => {
    const countedParticipantIndices = [...input.countedParticipantIndices].sort(
        (left, right) => left - right,
    );
    assertUniqueSortedIndices(
        countedParticipantIndices,
        'Ballot close participant',
    );

    return signProtocolPayload(privateKey, {
        ...input,
        phase: BALLOT_CLOSE_PHASE,
        messageType: 'ballot-close',
        countedParticipantIndices,
    });
};

/** Creates a signed threshold decryption-share payload for one option slot. */
export const createDecryptionSharePayload = async (
    privateKey: CryptoKey,
    input: Omit<
        DecryptionSharePayload,
        'messageType' | 'phase' | 'proof' | 'protocolVersion'
    > & {
        readonly protocolVersion?: string;
        readonly proof: DecryptionSharePayload['proof'] | DLEQProof;
    },
): Promise<SignedPayload<DecryptionSharePayload>> => {
    const payload: ProtocolPayloadInput<DecryptionSharePayload> = {
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
    input: Omit<
        TallyPublicationPayload,
        'messageType' | 'phase' | 'tally' | 'protocolVersion'
    > & {
        readonly protocolVersion?: string;
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
