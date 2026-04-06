class ThresholdElgamalError extends Error {
    public constructor(message: string) {
        super(message);
        this.name = new.target.name;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

/** Raised when a scalar value falls outside the expected mathematical domain. */
export class InvalidScalarError extends ThresholdElgamalError {}
/** Raised when a group element is not valid for the selected finite-field suite. */
export class InvalidGroupElementError extends ThresholdElgamalError {}
/** Reserved exported error class for future ciphertext-shape APIs. */
export class InvalidCiphertextError extends ThresholdElgamalError {}
/** Reserved exported error class for future share-oriented APIs. */
export class InvalidShareError extends ThresholdElgamalError {}
/** Reserved exported error class for future proof-oriented APIs. */
export class InvalidProofError extends ThresholdElgamalError {}
/** Raised when serialized payload bytes do not satisfy the required encoding. */
export class InvalidPayloadError extends ThresholdElgamalError {}
/** Raised when the requested suite or runtime capability is unavailable. */
export class UnsupportedSuiteError extends ThresholdElgamalError {}
/** Reserved exported error class for future transcript-matching APIs. */
export class TranscriptMismatchError extends ThresholdElgamalError {}
/** Reserved exported error class for future protocol phase APIs. */
export class PhaseViolationError extends ThresholdElgamalError {}
/** Raised when threshold or participant-count constraints are violated. */
export class ThresholdViolationError extends ThresholdElgamalError {}
/** Raised when a participant index falls outside the allowed roster range. */
export class IndexOutOfRangeError extends ThresholdElgamalError {}
/** Raised when a plaintext lies outside the allowed domain for the chosen mode. */
export class PlaintextDomainError extends ThresholdElgamalError {}
