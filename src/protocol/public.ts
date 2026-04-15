/**
 * Low-level protocol helpers for transcript hashing, generic signed payloads,
 * ballot proof verification, and protocol payload types.
 *
 * Use this module when you need to work directly with protocol messages rather
 * than the workflow-facing builders and verifiers from the root package.
 *
 * @module threshold-elgamal/protocol
 * @packageDocumentation
 */
export { signProtocolPayload } from './builders';
export { hashProtocolTranscript } from './transcript';
export { verifyBallotSubmissionPayloadsByOption } from './voting-ballots';
export { scoreVotingDomain } from './voting-codecs';
export type {
    EncodedCiphertext,
    EncodedCompactProof,
    EncodedDisjunctiveProof,
    ProtocolMessageType,
    ProtocolPayload,
} from './types';
