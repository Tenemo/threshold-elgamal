---
title: "encryptAdditiveWithRandomness"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold-elgamal](../) / encryptAdditiveWithRandomness

# Function: encryptAdditiveWithRandomness()

> **encryptAdditiveWithRandomness**(`message`, `publicKey`, `randomness`, `bound`, `group`): [`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext/)

Encrypts an additive plaintext with caller-supplied randomness.

The plaintext is encoded as `g^m`. The `bound` passed here validates the
single plaintext being encrypted and is not stored in the ciphertext.

## Parameters

### message

`bigint`

Plaintext in the range `0..bound`.

### publicKey

`bigint`

Additive-mode public key for the selected group.

### randomness

`bigint`

Encryption randomness in the range `1..q-1`.

### bound

`bigint`

Maximum plaintext accepted for this encryption call.

### group

[`ElgamalGroupInput`](../type-aliases/ElgamalGroupInput/)

Built-in group identifier shared by the key and ciphertext.

## Returns

[`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext/)

A fresh additive ciphertext `(c1, c2)`.

## Throws

[InvalidScalarError](../../core/classes/InvalidScalarError/) When `randomness` or `bound` is invalid.

## Throws

[InvalidGroupElementError](../../core/classes/InvalidGroupElementError/) When `publicKey` is not a valid
subgroup public key for `group`.

## Throws

[PlaintextDomainError](../../core/classes/PlaintextDomainError/) When `message` falls outside `0..bound`.

## Example

```ts
const ciphertext = encryptAdditiveWithRandomness(7n, publicKey, 42n, 20n, 'ffdhe3072');
```
