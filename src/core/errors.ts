class ThresholdElGamalError extends Error {
    public constructor(message: string) {
        super(message);
        this.name = new.target.name;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

/** Raised when a scalar value falls outside the expected mathematical domain. */
export class InvalidScalarError extends ThresholdElGamalError {}
/** Raised when a group element is not valid for the selected suite. */
export class InvalidGroupElementError extends ThresholdElGamalError {}
/** Raised when a participant index falls outside the valid `1..n` range. */
export class IndexOutOfRangeError extends ThresholdElGamalError {}
/** Raised when serialized payload bytes do not satisfy the required encoding. */
export class InvalidPayloadError extends ThresholdElGamalError {}
/** Raised when a proof transcript or response fails verification. */
export class InvalidProofError extends ThresholdElGamalError {}
/** Raised when the requested suite or runtime capability is unavailable. */
export class UnsupportedSuiteError extends ThresholdElGamalError {}
/** Raised when a plaintext lies outside the allowed domain for the chosen mode. */
export class PlaintextDomainError extends ThresholdElGamalError {}
/** Raised when a serialized or reconstructed share fails validation. */
export class InvalidShareError extends ThresholdElGamalError {}
/** Raised when a protocol step transition violates the state machine rules. */
export class PhaseViolationError extends ThresholdElGamalError {}
/** Raised when threshold parameters do not satisfy `1 <= k <= n`. */
export class ThresholdViolationError extends ThresholdElGamalError {}
/** Raised when transcript hashes or canonical bytes do not match expectations. */
export class TranscriptMismatchError extends ThresholdElGamalError {}
