/**
 * Low-level protocol helpers for transcript hashing, generic signed payloads,
 * registration-roster hashing, signature verification, ballot proof
 * verification, and protocol payload types.
 *
 * Use this module when you want protocol helpers grouped by subsystem instead
 * of importing them from the root package.
 *
 * @module threshold-elgamal/protocol
 * @packageDocumentation
 */
export { signProtocolPayload } from './builders';
export { hashProtocolTranscript } from './transcript';
export {
    hashRosterEntries,
    verifySignedProtocolPayloads,
    type RosterEntry,
    type VerifiedProtocolSignatures,
} from './verification';
export { verifyBallotSubmissionPayloadsByOption } from './voting-ballots';
export { scoreVotingDomain } from './voting-codecs';
export type {
    EncodedCiphertext,
    EncodedCompactProof,
    EncodedDisjunctiveProof,
    ProtocolMessageType,
    ProtocolPayload,
} from './types';
