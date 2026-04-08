---
title: "createDisjunctiveProof"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [proofs](../) / createDisjunctiveProof

# Function: createDisjunctiveProof()

> **createDisjunctiveProof**(`plaintext`, `randomness`, `ciphertext`, `publicKey`, `validValues`, `group`, `context`, `randomSource?`): `Promise`\<[`DisjunctiveProof`](../type-aliases/DisjunctiveProof/)\>

Creates a CDS94-style disjunctive proof for additive ElGamal plaintexts.

## Parameters

### plaintext

`bigint`

Actual plaintext encoded in the ciphertext.

### randomness

`bigint`

Encryption randomness used for the ciphertext.

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

### randomSource?

[`RandomBytesSource`](../../core/type-aliases/RandomBytesSource/)

Optional random source used for deterministic tests.

## Returns

`Promise`\<[`DisjunctiveProof`](../type-aliases/DisjunctiveProof/)\>

Compact disjunctive proof with one branch per valid value.
