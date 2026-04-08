---
title: "verifyDisjunctiveProof"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [proofs](../) / verifyDisjunctiveProof

# Function: verifyDisjunctiveProof()

> **verifyDisjunctiveProof**(`proof`, `ciphertext`, `publicKey`, `validValues`, `group`, `context`): `Promise`\<`boolean`\>

Verifies a CDS94-style disjunctive proof for additive ElGamal plaintexts.

## Parameters

### proof

[`DisjunctiveProof`](../type-aliases/DisjunctiveProof/)

Compact disjunctive proof with one branch per valid value.

### ciphertext

[`ElgamalCiphertext`](../../threshold-elgamal/type-aliases/ElgamalCiphertext/)

Fresh additive ciphertext.

### publicKey

`bigint`

Additive-mode public key.

### validValues

readonly `bigint`[]

Ordered set of valid plaintext values.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup/)

Resolved group definition.

### context

[`ProofContext`](../type-aliases/ProofContext/)

Fiat-Shamir binding context.

## Returns

`Promise`\<`boolean`\>

`true` when the proof verifies.
