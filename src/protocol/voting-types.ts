import type { EncodedPoint } from '../core/types.js';
import type { KeyDerivationConfirmationPolicy } from '../dkg/verification-types.js';
import type { VerifiedDKGTranscript } from '../dkg/verification.js';
import type { DecryptionShare } from '../threshold/index.js';

import type {
    VerifiedBallotAggregation,
    VerifiedOptionBallotAggregation,
} from './ballots.js';
import type {
    BallotClosePayload,
    BallotSubmissionPayload,
    DecryptionSharePayload,
    ElectionManifest,
    SignedPayload,
    TallyPublicationPayload,
} from './types.js';

/**
 * Input bundle for verifying typed ballot payloads.
 */
type VerifyBallotSubmissionPayloadsInput = {
    readonly ballotPayloads: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly publicKey: EncodedPoint;
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
};

/** Input bundle for verifying typed ballot payloads across all options. */
export type VerifyBallotSubmissionPayloadsByOptionInput =
    VerifyBallotSubmissionPayloadsInput;

/** Verified typed decryption-share payload. */
export type VerifiedDecryptionSharePayload = {
    readonly payload: SignedPayload<DecryptionSharePayload>;
    readonly share: DecryptionShare;
};

/** Verified aggregate input for one option slot. */
export type OptionAggregateInput = {
    readonly optionIndex: number;
    readonly aggregate: VerifiedBallotAggregation['aggregate'];
};

/** Verified decryption shares grouped by option slot. */
export type VerifiedOptionDecryptionShares = {
    readonly optionIndex: number;
    readonly decryptionShares: readonly VerifiedDecryptionSharePayload[];
};

/** Input bundle for verifying typed decryption-share payloads by option. */
export type VerifyDecryptionSharePayloadsByOptionInput = {
    readonly aggregates: readonly OptionAggregateInput[];
    readonly dkg: VerifiedDKGTranscript;
    readonly decryptionSharePayloads: readonly SignedPayload<DecryptionSharePayload>[];
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
};

/** Input bundle for verifying one full published tally set across all options. */
export type VerifyPublishedVotingResultsInput = {
    readonly manifest: ElectionManifest;
    readonly sessionId: string;
    readonly dkgTranscript: readonly SignedPayload[];
    /** Defaults to `'required'`; set to `'optional'` only when replaying a legacy DKG transcript without confirmations. */
    readonly keyDerivationConfirmationPolicy?: KeyDerivationConfirmationPolicy;
    readonly ballotPayloads: readonly SignedPayload<BallotSubmissionPayload>[];
    readonly ballotClosePayload: SignedPayload<BallotClosePayload>;
    readonly decryptionSharePayloads: readonly SignedPayload<DecryptionSharePayload>[];
    readonly tallyPublications?: readonly SignedPayload<TallyPublicationPayload>[];
};

/** Verified published tally for one option slot. */
export type VerifiedPublishedOptionVotingResult = {
    readonly optionIndex: number;
    readonly ballots: VerifiedOptionBallotAggregation;
    readonly decryptionShares: readonly VerifiedDecryptionSharePayload[];
    readonly tally: bigint;
};
