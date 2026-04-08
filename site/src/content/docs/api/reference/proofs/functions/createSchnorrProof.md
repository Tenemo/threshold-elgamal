---
title: "createSchnorrProof"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [proofs](../) / createSchnorrProof

# Function: createSchnorrProof()

> **createSchnorrProof**(`secret`, `statement`, `group`, `context`, `randomSource?`): `Promise`\<[`SchnorrProof`](../type-aliases/SchnorrProof/)\>

Creates a compact additive-form Schnorr proof of knowledge.

## Parameters

### secret

`bigint`

Witness scalar.

### statement

`bigint`

Statement element `g^secret mod p`.

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

`Promise`\<[`SchnorrProof`](../type-aliases/SchnorrProof/)\>

Compact Schnorr proof `(challenge, response)`.
