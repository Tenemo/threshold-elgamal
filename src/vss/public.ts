/**
 * Public verifiable-secret-sharing helpers for Feldman and Pedersen
 * commitments and shares.
 *
 * @module threshold-elgamal/vss
 * @packageDocumentation
 */
export { generateFeldmanCommitments, verifyFeldmanShare } from './feldman';
export {
    derivePedersenShares,
    generatePedersenCommitments,
    verifyPedersenShare,
} from './pedersen';
export type {
    FeldmanCommitments,
    PedersenCommitments,
    PedersenShare,
} from './types';
