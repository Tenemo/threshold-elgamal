---
title: "verifySchnorrProof"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [proofs](../) / verifySchnorrProof

# Function: verifySchnorrProof()

> **verifySchnorrProof**(`proof`, `statement`, `group`, `context`): `Promise`\<`boolean`\>

Verifies a compact additive-form Schnorr proof.

## Parameters

### proof

[`SchnorrProof`](../type-aliases/SchnorrProof/)

Compact Schnorr proof `(challenge, response)`.

### statement

`bigint`

Statement element `g^secret mod p`.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup/)

Resolved group definition.

### context

[`ProofContext`](../type-aliases/ProofContext/)

Fiat-Shamir binding context.

## Returns

`Promise`\<`boolean`\>

`true` when the proof verifies.
