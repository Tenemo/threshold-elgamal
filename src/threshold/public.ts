/**
 * Threshold-share and bounded tally-reconstruction helpers.
 *
 * Use this module when you need to prepare aggregates, create decryption
 * shares, or reconstruct tallies directly.
 *
 * @module threshold-elgamal/threshold
 * @packageDocumentation
 */
export {
    combineDecryptionShares,
    createDecryptionShare,
    prepareAggregateForDecryption,
} from './decrypt';
export type {
    AggregateDecryptionPreparationInput,
    DecryptionShare,
    Share,
    VerifiedAggregateCiphertext,
} from './types';
