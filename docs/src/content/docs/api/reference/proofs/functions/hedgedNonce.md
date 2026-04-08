---
title: "hedgedNonce"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [proofs](../) / hedgedNonce

# Function: hedgedNonce()

> **hedgedNonce**(`secret`, `context`, `group`, `randomSource?`): `Promise`\<`bigint`\>

Generates a hedged nonce with domain-separated wide reduction.

## Parameters

### secret

`bigint`

Secret scalar used to hedge the nonce derivation.

### context

`Uint8Array`

Deterministic context bytes for the proof statement.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup/)

Resolved group definition.

### randomSource?

[`RandomBytesSource`](../../core/type-aliases/RandomBytesSource/)

Optional random source used for deterministic tests.

## Returns

`Promise`\<`bigint`\>

A nonce reduced modulo `q`.
