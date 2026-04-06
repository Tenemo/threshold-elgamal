[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / decryptAdditive

# Function: decryptAdditive()

> **decryptAdditive**(`ciphertext`, `privateKey`, `group`, `bound`): `bigint`

Decrypts an additive ciphertext and recovers the bounded plaintext with
baby-step giant-step.

The supplied `bound` must match the operational range used for the ciphertext
or decryption may fail even when the key is correct.

## Parameters

### ciphertext

[`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext.md)

### privateKey

`bigint`

### group

[`ElgamalGroupInput`](../type-aliases/ElgamalGroupInput.md)

### bound

`bigint`

## Returns

`bigint`

## Throws

[InvalidScalarError](../classes/InvalidScalarError.md) When `bound` is missing or invalid.

## Throws

[PlaintextDomainError](../classes/PlaintextDomainError.md) When the decrypted plaintext lies
outside the supplied bound.

## Example

```ts
const message = decryptAdditive(ciphertext, privateKey, 'ffdhe3072', 20n);
```
