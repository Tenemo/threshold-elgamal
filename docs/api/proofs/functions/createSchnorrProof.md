[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [proofs](../index.md) / createSchnorrProof

# Function: createSchnorrProof()

> **createSchnorrProof**(`secret`, `statement`, `group`, `context`, `randomSource?`): `Promise`\<[`SchnorrProof`](../type-aliases/SchnorrProof.md)\>

Creates a compact additive-form Schnorr proof of knowledge.

## Parameters

### secret

`bigint`

Witness scalar.

### statement

`bigint`

Statement element `g^secret mod p`.

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

`Promise`\<[`SchnorrProof`](../type-aliases/SchnorrProof.md)\>

Compact Schnorr proof `(challenge, response)`.
