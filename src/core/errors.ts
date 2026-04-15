/**
 * Shared error taxonomy for the package.
 *
 * Public helpers throw these errors when callers violate mathematical,
 * encoding, transcript, or workflow invariants.
 */
class ThresholdElGamalError extends Error {
    public constructor(message: string) {
        super(message);
        this.name = new.target.name;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

/**
 * Raised when a scalar value falls outside the expected field or subgroup
 * domain for the current operation.
 */
export class InvalidScalarError extends ThresholdElGamalError {}
/**
 * Raised when a point or public key is not a canonical member of the selected
 * cryptographic group.
 */
export class InvalidGroupElementError extends ThresholdElGamalError {}
/**
 * Raised when a participant index falls outside the supported `1..n`
 * numbering scheme used across the protocol.
 */
export class IndexOutOfRangeError extends ThresholdElGamalError {}
/**
 * Raised when a payload, transcript field, manifest field, or serialized value
 * does not satisfy the package's canonical encoding rules.
 */
export class InvalidPayloadError extends ThresholdElGamalError {}
/**
 * Raised when a Schnorr, DLEQ, or disjunctive proof transcript fails
 * structural checks or cryptographic verification.
 */
export class InvalidProofError extends ThresholdElGamalError {}
/**
 * Raised when the requested suite or required runtime capability is unavailable
 * in the current environment.
 */
export class UnsupportedSuiteError extends ThresholdElGamalError {}
/**
 * Raised when an additive plaintext falls outside the explicitly bounded domain
 * that the current workflow promised to support.
 */
export class PlaintextDomainError extends ThresholdElGamalError {}
/**
 * Raised when a serialized share, decrypted share envelope, or reconstructed
 * share set fails threshold-specific validation.
 */
export class InvalidShareError extends ThresholdElGamalError {}
/**
 * Raised when a published payload claims to belong to a protocol phase that
 * does not match the supported ceremony state machine.
 */
export class PhaseViolationError extends ThresholdElGamalError {}
/**
 * Raised when threshold parameters or participant counts violate the supported
 * `1 <= k <= n` relationship or the package's honest-majority policy.
 */
export class ThresholdViolationError extends ThresholdElGamalError {}
/**
 * Raised when transcript hashes, manifest hashes, or other canonical digest
 * commitments do not match the values claimed by published payloads.
 */
export class TranscriptMismatchError extends ThresholdElGamalError {}
