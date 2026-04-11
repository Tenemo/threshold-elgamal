import type { GroupName } from '../core/types.js';

/** Common Fiat-Shamir context fields used by the shipped proof systems. */
export type ProofContext = {
    /** Protocol version string bound into the transcript. */
    readonly protocolVersion: string;
    /** Group suite name bound into the transcript. */
    readonly suiteId: GroupName;
    /** Canonical election-manifest hash or equivalent protocol root. */
    readonly manifestHash: string;
    /** Ceremony or transcript session identifier. */
    readonly sessionId: string;
    /** Domain-separation label for the proof domain. */
    readonly label: string;
    /** Optional participant index for trustee-bound proofs. */
    readonly participantIndex?: number;
    /** Optional coefficient index for Feldman coefficient proofs. */
    readonly coefficientIndex?: number;
    /** Optional voter index for ballot proofs alongside the shared manifest/session binding. */
    readonly voterIndex?: number;
    /** Optional ballot option index so ballot proofs stay bound to one option slot. */
    readonly optionIndex?: number;
};

/** Compact Schnorr proof encoded as challenge and response only. */
export type SchnorrProof = {
    readonly challenge: bigint;
    readonly response: bigint;
};

/** Compact Chaum-Pedersen proof encoded as challenge and response only. */
export type DLEQProof = {
    readonly challenge: bigint;
    readonly response: bigint;
};

/** One branch of a CDS94 disjunctive proof. */
export type DisjunctiveBranch = {
    readonly challenge: bigint;
    readonly response: bigint;
};

/** A disjunctive proof over an ordered set of valid plaintext values. */
export type DisjunctiveProof = {
    readonly branches: readonly DisjunctiveBranch[];
};
