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

Plaintext in the range `0..bound`.

### publicKey

`bigint`

Additive-mode public key for the selected group.

### group

[`ElgamalGroupInput`](../type-aliases/ElgamalGroupInput.md)

Built-in group identifier shared by the key and ciphertext.

### bound

`bigint`

Maximum plaintext accepted for this encryption call.

## Returns

[`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext.md)

A fresh additive ciphertext `(c1, c2)`.

## Throws

[InvalidScalarError](../../core/classes/InvalidScalarError.md) When `bound` is missing or invalid.

## Throws

[InvalidGroupElementError](../../core/classes/InvalidGroupElementError.md) When `publicKey` is not a valid
subgroup public key for `group`.

## Throws

[PlaintextDomainError](../../core/classes/PlaintextDomainError.md) When `message` falls outside `0..bound`.

## Example

```ts
const ciphertext = encryptAdditive(6n, publicKey, 'ffdhe3072', 20n);
```
