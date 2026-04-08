[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [proofs](../index.md) / createDisjunctiveProof

# Function: createDisjunctiveProof()

> **createDisjunctiveProof**(`plaintext`, `randomness`, `ciphertext`, `publicKey`, `validValues`, `group`, `context`, `randomSource?`): `Promise`\<[`DisjunctiveProof`](../type-aliases/DisjunctiveProof.md)\>

Creates a CDS94-style disjunctive proof for additive ElGamal plaintexts.

## Parameters

### plaintext

`bigint`

Actual plaintext encoded in the ciphertext.

### randomness

`bigint`

Encryption randomness used for the ciphertext.

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

### randomSource?

[`RandomBytesSource`](../../core/type-aliases/RandomBytesSource.md)

Optional random source used for deterministic tests.

## Returns

`Promise`\<[`DisjunctiveProof`](../type-aliases/DisjunctiveProof.md)\>

Compact disjunctive proof with one branch per valid value.
