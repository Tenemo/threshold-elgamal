---
title: "decryptAdditive"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold-elgamal](../) / decryptAdditive

# Function: decryptAdditive()

> **decryptAdditive**(`ciphertext`, `privateKey`, `group`, `bound`): `bigint`

Decrypts an additive ciphertext and recovers the bounded plaintext with
baby-step giant-step.

The supplied `bound` must cover the plaintext you expect to recover. For
aggregate decryption this is usually the maximum tally, which can be larger
than the bounds used to validate individual plaintexts during encryption. The
library does not store or authenticate this bound inside the ciphertext.

## Parameters

### ciphertext

[`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext/)

Additive ciphertext to decrypt.

### privateKey

`bigint`

Private key in the range `1..q-1`.

### group

[`ElgamalGroupInput`](../type-aliases/ElgamalGroupInput/)

Built-in group identifier shared by the key and ciphertext.

### bound

`bigint`

Maximum plaintext to search for during bounded recovery.

## Returns

`bigint`

The recovered plaintext as a bigint.

## Throws

[InvalidScalarError](../../core/classes/InvalidScalarError/) When `bound` is missing or invalid.

## Throws

[InvalidGroupElementError](../../core/classes/InvalidGroupElementError/) When `ciphertext` is not valid for
the selected group.

## Throws

[PlaintextDomainError](../../core/classes/PlaintextDomainError/) When the decrypted plaintext lies
outside the supplied bound.

## Example

```ts
const message = decryptAdditive(ciphertext, privateKey, 'ffdhe3072', 20n);
```
