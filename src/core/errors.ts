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
/** Raised when serialized payload bytes do not satisfy the required encoding. */
export class InvalidPayloadError extends ThresholdElgamalError {}
/** Raised when the requested suite or runtime capability is unavailable. */
export class UnsupportedSuiteError extends ThresholdElgamalError {}
/** Raised when a plaintext lies outside the allowed domain for the chosen mode. */
export class PlaintextDomainError extends ThresholdElgamalError {}
