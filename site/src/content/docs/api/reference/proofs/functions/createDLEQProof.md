---
title: "createDLEQProof"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [proofs](../) / createDLEQProof

# Function: createDLEQProof()

> **createDLEQProof**(`secret`, `statement`, `group`, `context`, `randomSource?`): `Promise`\<[`DLEQProof`](../type-aliases/DLEQProof/)\>

Creates a compact additive-form Chaum-Pedersen proof of equal discrete logs.

## Parameters

### secret

`bigint`

Witness scalar.

### statement

[`DLEQStatement`](../type-aliases/DLEQStatement/)

DLEQ statement over `(g, publicKey)` and `(c1, share)`.

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

`Promise`\<[`DLEQProof`](../type-aliases/DLEQProof/)\>

Compact DLEQ proof `(challenge, response)`.
