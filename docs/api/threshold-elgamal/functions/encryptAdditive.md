[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / encryptAdditive

# Function: encryptAdditive()

> **encryptAdditive**(`message`, `publicKey`, `group`, `bound`): [`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext.md)

Encrypts an additive plaintext with fresh random `r in 1..q-1`.

Use this mode for confidential sums where plaintexts stay within a known
bounded range.

## Parameters

### message

`bigint`

### publicKey

`bigint`

### group

[`ElgamalGroupInput`](../type-aliases/ElgamalGroupInput.md)

### bound

`bigint`

## Returns

[`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext.md)

## Throws

[InvalidScalarError](../classes/InvalidScalarError.md) When `bound` is missing or invalid.

## Throws

[PlaintextDomainError](../classes/PlaintextDomainError.md) When `message` falls outside `0..bound`.

## Example

```ts
const ciphertext = encryptAdditive(6n, publicKey, 'ffdhe3072', 20n);
```
