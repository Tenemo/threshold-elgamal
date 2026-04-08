---
title: "verifyDLEQProof"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [proofs](../) / verifyDLEQProof

# Function: verifyDLEQProof()

> **verifyDLEQProof**(`proof`, `statement`, `group`, `context`): `Promise`\<`boolean`\>

Verifies a compact additive-form Chaum-Pedersen proof of equal discrete logs.

## Parameters

### proof

[`DLEQProof`](../type-aliases/DLEQProof/)

Compact DLEQ proof `(challenge, response)`.

### statement

[`DLEQStatement`](../type-aliases/DLEQStatement/)

DLEQ statement over `(g, publicKey)` and `(c1, share)`.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup/)

Resolved group definition.

### context

[`ProofContext`](../type-aliases/ProofContext/)

Fiat-Shamir binding context.

## Returns

`Promise`\<`boolean`\>

`true` when the proof verifies.
