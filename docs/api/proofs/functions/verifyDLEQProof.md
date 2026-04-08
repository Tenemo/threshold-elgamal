[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [proofs](../index.md) / verifyDLEQProof

# Function: verifyDLEQProof()

> **verifyDLEQProof**(`proof`, `statement`, `group`, `context`): `Promise`\<`boolean`\>

Verifies a compact additive-form Chaum-Pedersen proof of equal discrete logs.

## Parameters

### proof

[`DLEQProof`](../type-aliases/DLEQProof.md)

Compact DLEQ proof `(challenge, response)`.

### statement

[`DLEQStatement`](../type-aliases/DLEQStatement.md)

DLEQ statement over `(g, publicKey)` and `(c1, share)`.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup.md)

Resolved group definition.

### context

[`ProofContext`](../type-aliases/ProofContext.md)

Fiat-Shamir binding context.

## Returns

`Promise`\<`boolean`\>

`true` when the proof verifies.
