[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [proofs](../index.md) / verifySchnorrProof

# Function: verifySchnorrProof()

> **verifySchnorrProof**(`proof`, `statement`, `group`, `context`): `Promise`\<`boolean`\>

Verifies a compact additive-form Schnorr proof.

## Parameters

### proof

[`SchnorrProof`](../type-aliases/SchnorrProof.md)

Compact Schnorr proof `(challenge, response)`.

### statement

`bigint`

Statement element `g^secret mod p`.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup.md)

Resolved group definition.

### context

[`ProofContext`](../type-aliases/ProofContext.md)

Fiat-Shamir binding context.

## Returns

`Promise`\<`boolean`\>

`true` when the proof verifies.
