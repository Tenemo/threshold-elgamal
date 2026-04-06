[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / encryptAdditiveWithRandomness

# Function: encryptAdditiveWithRandomness()

> **encryptAdditiveWithRandomness**(`message`, `publicKey`, `randomness`, `bound`, `group`): [`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext.md)

Encrypts an additive plaintext with caller-supplied randomness.

The plaintext is encoded as `g^m`, so decryption succeeds only when the same
bound is later supplied to the bounded discrete-log solver.

## Parameters

### message

`bigint`

### publicKey

`bigint`

### randomness

`bigint`

### bound

`bigint`

### group

[`ElgamalGroupInput`](../type-aliases/ElgamalGroupInput.md)

## Returns

[`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext.md)

## Throws

[InvalidScalarError](../classes/InvalidScalarError.md) When `randomness` or `bound` is invalid.

## Throws

[PlaintextDomainError](../classes/PlaintextDomainError.md) When `message` falls outside `0..bound`.

## Example

```ts
const ciphertext = encryptAdditiveWithRandomness(7n, publicKey, 42n, 20n, 'ffdhe3072');
```
