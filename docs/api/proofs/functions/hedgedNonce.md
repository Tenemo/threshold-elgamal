[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [proofs](../index.md) / hedgedNonce

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

[`CryptoGroup`](../../core/type-aliases/CryptoGroup.md)

Resolved group definition.

### randomSource?

[`RandomBytesSource`](../../core/type-aliases/RandomBytesSource.md)

Optional random source used for deterministic tests.

## Returns

`Promise`\<`bigint`\>

A nonce reduced modulo `q`.
