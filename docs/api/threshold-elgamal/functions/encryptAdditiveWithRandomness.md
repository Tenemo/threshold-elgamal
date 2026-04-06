[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / encryptAdditiveWithRandomness

# Function: encryptAdditiveWithRandomness()

> **encryptAdditiveWithRandomness**(`message`, `publicKey`, `randomness`, `bound`, `group`): [`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext.md)

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

[`ElgamalGroupInput`](../type-aliases/ElgamalGroupInput.md)

Built-in group identifier shared by the key and ciphertext.

## Returns

[`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext.md)

A fresh additive ciphertext `(c1, c2)`.

## Throws

[InvalidScalarError](../../core/classes/InvalidScalarError.md) When `randomness` or `bound` is invalid.

## Throws

[InvalidGroupElementError](../../core/classes/InvalidGroupElementError.md) When `publicKey` is not a valid
subgroup public key for `group`.

## Throws

[PlaintextDomainError](../../core/classes/PlaintextDomainError.md) When `message` falls outside `0..bound`.

## Example

```ts
const ciphertext = encryptAdditiveWithRandomness(7n, publicKey, 42n, 20n, 'ffdhe3072');
```
