/**
 * Proof-system helpers for Schnorr, DLEQ, and disjunctive ballot proofs.
 *
 * Use this module when you need to create or verify proof objects directly.
 *
 * @module threshold-elgamal/proofs
 * @packageDocumentation
 */
export { createDisjunctiveProof, verifyDisjunctiveProof } from './disjunctive';
export { createDLEQProof, type DLEQStatement, verifyDLEQProof } from './dleq';
export { createSchnorrProof, verifySchnorrProof } from './schnorr';
export type {
    DLEQProof,
    DisjunctiveProof,
    ProofContext,
    SchnorrProof,
} from './types';
