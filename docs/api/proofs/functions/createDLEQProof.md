[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [proofs](../index.md) / createDLEQProof

# Function: createDLEQProof()

> **createDLEQProof**(`secret`, `statement`, `group`, `context`, `randomSource?`): `Promise`\<[`DLEQProof`](../type-aliases/DLEQProof.md)\>

Creates a compact additive-form Chaum-Pedersen proof of equal discrete logs.

## Parameters

### secret

`bigint`

Witness scalar.

### statement

[`DLEQStatement`](../type-aliases/DLEQStatement.md)

DLEQ statement over `(g, publicKey)` and `(c1, share)`.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup.md)

Resolved group definition.

### context

[`ProofContext`](../type-aliases/ProofContext.md)

Fiat-Shamir binding context.

### randomSource?

[`RandomBytesSource`](../../core/type-aliases/RandomBytesSource.md)

Optional random source used for deterministic tests.

## Returns

`Promise`\<[`DLEQProof`](../type-aliases/DLEQProof.md)\>

Compact DLEQ proof `(challenge, response)`.
