---
title: "proofs"
description: "Generated reference page for the `proofs` export surface."
editUrl: false
sidebar:
  order: 5
---
[**threshold-elgamal**](../)

***

[threshold-elgamal](../modules/) / proofs

# proofs

Zero-knowledge proof helpers for commitments, decryption shares, and ballot
validity proofs.

This module ships additive-form Schnorr, DLEQ, and disjunctive proof
helpers, plus hedged nonce generation.

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [DisjunctiveBranch](type-aliases/DisjunctiveBranch/) | One branch of a CDS94 disjunctive proof. |
| [DisjunctiveProof](type-aliases/DisjunctiveProof/) | A disjunctive proof over an ordered set of valid plaintext values. |
| [DLEQProof](type-aliases/DLEQProof/) | Compact Chaum-Pedersen proof encoded as challenge and response only. |
| [DLEQStatement](type-aliases/DLEQStatement/) | Statement tuple for a Chaum-Pedersen equality-of-discrete-logs proof. |
| [ProofContext](type-aliases/ProofContext/) | Common Fiat-Shamir context fields used by the shipped proof systems. |
| [SchnorrProof](type-aliases/SchnorrProof/) | Compact Schnorr proof encoded as challenge and response only. |

## Functions

| Function | Description |
| ------ | ------ |
| [createDisjunctiveProof](functions/createDisjunctiveProof/) | Creates a CDS94-style disjunctive proof for additive ElGamal plaintexts. |
| [createDLEQProof](functions/createDLEQProof/) | Creates a compact additive-form Chaum-Pedersen proof of equal discrete logs. |
| [createSchnorrProof](functions/createSchnorrProof/) | Creates a compact additive-form Schnorr proof of knowledge. |
| [hedgedNonce](functions/hedgedNonce/) | Generates a hedged nonce with domain-separated wide reduction. |
| [verifyDisjunctiveProof](functions/verifyDisjunctiveProof/) | Verifies a CDS94-style disjunctive proof for additive ElGamal plaintexts. |
| [verifyDLEQProof](functions/verifyDLEQProof/) | Verifies a compact additive-form Chaum-Pedersen proof of equal discrete logs. |
| [verifySchnorrProof](functions/verifySchnorrProof/) | Verifies a compact additive-form Schnorr proof. |
