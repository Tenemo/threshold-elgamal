class ThresholdElgamalError extends Error {
    public constructor(message: string) {
        super(message);
        this.name = new.target.name;
        Object.setPrototypeOf(this, new.target.prototype);
    }
}

export class InvalidScalarError extends ThresholdElgamalError {}
export class InvalidGroupElementError extends ThresholdElgamalError {}
export class InvalidCiphertextError extends ThresholdElgamalError {}
export class InvalidShareError extends ThresholdElgamalError {}
export class InvalidProofError extends ThresholdElgamalError {}
export class InvalidPayloadError extends ThresholdElgamalError {}
export class UnsupportedSuiteError extends ThresholdElgamalError {}
export class TranscriptMismatchError extends ThresholdElgamalError {}
export class PhaseViolationError extends ThresholdElgamalError {}
export class ThresholdViolationError extends ThresholdElgamalError {}
export class IndexOutOfRangeError extends ThresholdElgamalError {}
export class PlaintextDomainError extends ThresholdElgamalError {}
