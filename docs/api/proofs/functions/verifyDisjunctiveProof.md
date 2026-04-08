[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [proofs](../index.md) / verifyDisjunctiveProof

# Function: verifyDisjunctiveProof()

> **verifyDisjunctiveProof**(`proof`, `ciphertext`, `publicKey`, `validValues`, `group`, `context`): `Promise`\<`boolean`\>

Verifies a CDS94-style disjunctive proof for additive ElGamal plaintexts.

## Parameters

### proof

[`DisjunctiveProof`](../type-aliases/DisjunctiveProof.md)

Compact disjunctive proof with one branch per valid value.

### ciphertext

[`ElgamalCiphertext`](../../threshold-elgamal/type-aliases/ElgamalCiphertext.md)

Fresh additive ciphertext.

### publicKey

`bigint`

Additive-mode public key.

### validValues

readonly `bigint`[]

Ordered set of valid plaintext values.

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup.md)

Resolved group definition.

### context

[`ProofContext`](../type-aliases/ProofContext.md)

Fiat-Shamir binding context.

## Returns

`Promise`\<`boolean`\>

`true` when the proof verifies.
