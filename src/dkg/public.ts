/**
 * Public DKG transcript helpers and share-envelope codecs.
 *
 * Use this module when you need direct access to transcript replay, derived
 * trustee verification keys, or encrypted share-envelope encoding.
 *
 * @module threshold-elgamal/dkg
 * @packageDocumentation
 */
export {
    deriveJointPublicKey,
    deriveTranscriptVerificationKey,
    verifyDKGTranscript,
} from './verification';
export {
    decodePedersenShareEnvelope,
    encodePedersenShareEnvelope,
} from './pedersen-share-codec';
export type {
    VerifyDKGTranscriptInput,
    VerifiedDKGTranscript,
} from './verification';
