[**threshold-elgamal**](../index.md)

***

[threshold-elgamal](../modules.md) / proofs

# proofs

Zero-knowledge proof helpers for commitments, decryption shares, and ballot
validity proofs.

This module ships additive-form Schnorr, DLEQ, and disjunctive proof
helpers, plus hedged nonce generation.

## Type aliases

| Type alias | Description |
| ------ | ------ |
| [DisjunctiveBranch](type-aliases/DisjunctiveBranch.md) | One branch of a CDS94 disjunctive proof. |
| [DisjunctiveProof](type-aliases/DisjunctiveProof.md) | A disjunctive proof over an ordered set of valid plaintext values. |
| [DLEQProof](type-aliases/DLEQProof.md) | Compact Chaum-Pedersen proof encoded as challenge and response only. |
| [DLEQStatement](type-aliases/DLEQStatement.md) | Statement tuple for a Chaum-Pedersen equality-of-discrete-logs proof. |
| [ProofContext](type-aliases/ProofContext.md) | Common Fiat-Shamir context fields used by the shipped proof systems. |
| [SchnorrProof](type-aliases/SchnorrProof.md) | Compact Schnorr proof encoded as challenge and response only. |

## Functions

| Function | Description |
| ------ | ------ |
| [createDisjunctiveProof](functions/createDisjunctiveProof.md) | Creates a CDS94-style disjunctive proof for additive ElGamal plaintexts. |
| [createDLEQProof](functions/createDLEQProof.md) | Creates a compact additive-form Chaum-Pedersen proof of equal discrete logs. |
| [createSchnorrProof](functions/createSchnorrProof.md) | Creates a compact additive-form Schnorr proof of knowledge. |
| [hedgedNonce](functions/hedgedNonce.md) | Generates a hedged nonce with domain-separated wide reduction. |
| [verifyDisjunctiveProof](functions/verifyDisjunctiveProof.md) | Verifies a CDS94-style disjunctive proof for additive ElGamal plaintexts. |
| [verifyDLEQProof](functions/verifyDLEQProof.md) | Verifies a compact additive-form Chaum-Pedersen proof of equal discrete logs. |
| [verifySchnorrProof](functions/verifySchnorrProof.md) | Verifies a compact additive-form Schnorr proof. |
