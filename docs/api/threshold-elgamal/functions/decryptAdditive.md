[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / decryptAdditive

# Function: decryptAdditive()

> **decryptAdditive**(`ciphertext`, `privateKey`, `group`, `bound`): `bigint`

## Parameters

### ciphertext

[`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext.md)

Additive ciphertext to decrypt.

### privateKey

`bigint`

Private key in the range `1..q-1`.

### group

[`ElgamalGroupInput`](../type-aliases/ElgamalGroupInput.md)

Built-in group identifier shared by the key and ciphertext.

### bound

`bigint`

Maximum plaintext to search for during bounded recovery.

## Returns

`bigint`

The recovered plaintext as a bigint.
