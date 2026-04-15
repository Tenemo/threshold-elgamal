/**
 * Low-level additive ElGamal helpers.
 *
 * Use this module when you need direct ciphertext construction primitives
 * instead of the higher-level protocol payload builders.
 *
 * @module threshold-elgamal/elgamal
 * @packageDocumentation
 */
export { encryptAdditiveWithRandomness } from './additive';
export type { ElGamalCiphertext } from './types';
