import type { CryptoGroup } from '../core/index.js';
import type { EncodedPoint } from '../core/types.js';
import type {
    ComplaintPayload,
    ElectionManifest,
    EncryptedDualSharePayload,
    FeldmanCommitmentPayload,
    RegistrationPayload,
    SignedPayload,
} from '../protocol/types.js';
import type { PedersenShare } from '../vss/types.js';

import type { FinalizedPhaseCheckpoint } from './checkpoints.js';
import type { DKGProtocol } from './types.js';

/** Share contribution accepted from one qualified dealer. */
export type AcceptedShareContribution = {
    readonly dealerIndex: number;
    readonly share: PedersenShare;
};

/** Input bundle for verifying a DKG transcript. */
export type VerifyDKGTranscriptInput = {
    readonly protocol: DKGProtocol;
    readonly transcript: readonly SignedPayload[];
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
};

/** Verified DKG transcript result with reusable derived ceremony material. */
export type VerifiedDKGTranscript = {
    readonly acceptedComplaints: readonly ComplaintPayload[];
    readonly derivedPublicKey: EncodedPoint;
    readonly feldmanCommitments: readonly {
        readonly dealerIndex: number;
        readonly commitments: readonly EncodedPoint[];
    }[];
    readonly group: CryptoGroup;
    readonly manifestAccepted: readonly number[];
    readonly phaseCheckpoints: readonly FinalizedPhaseCheckpoint[];
    readonly qual: readonly number[];
    readonly qualHash: string;
    readonly registrations: readonly SignedPayload<RegistrationPayload>[];
    readonly rosterHash: string;
};

export type EncryptedShareMatrix = {
    readonly encryptedShares: readonly SignedPayload<EncryptedDualSharePayload>[];
    readonly bySlot: ReadonlyMap<
        string,
        SignedPayload<EncryptedDualSharePayload>
    >;
    readonly byComplaintKey: ReadonlyMap<
        string,
        SignedPayload<EncryptedDualSharePayload>
    >;
};

export type ParsedFeldmanCommitment = {
    readonly dealerIndex: number;
    readonly commitments: readonly EncodedPoint[];
    readonly payload: FeldmanCommitmentPayload;
};

export type ResolvePhaseCheckpointInput = {
    readonly transcript: readonly SignedPayload[];
    readonly checkpointPhase: number;
    readonly threshold: number;
    readonly participantCount: number;
    readonly signerUniverse: ReadonlySet<number>;
    readonly qualUniverse: ReadonlySet<number>;
};
