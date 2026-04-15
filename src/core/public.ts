/**
 * Low-level core helpers for arithmetic, error handling, and group constants.
 *
 * Use this module when you need primitives that sit below the voting workflow
 * surface exposed by the root package.
 *
 * @module threshold-elgamal/core
 * @packageDocumentation
 */
export {
    IndexOutOfRangeError,
    InvalidGroupElementError,
    InvalidPayloadError,
    InvalidProofError,
    InvalidScalarError,
    InvalidShareError,
    PhaseViolationError,
    PlaintextDomainError,
    ThresholdViolationError,
    TranscriptMismatchError,
    UnsupportedSuiteError,
} from './errors';
export { modQ } from './bigint';
export { RISTRETTO_GROUP } from './groups';
export type { EncodedPoint } from './types';
