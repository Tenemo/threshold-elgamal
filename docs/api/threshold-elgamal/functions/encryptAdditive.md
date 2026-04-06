[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / encryptAdditive

# Function: encryptAdditive()

> **encryptAdditive**(`message`, `publicKey`, `group`, `bound`): [`ElgamalCiphertext`](../type-aliases/ElgamalCiphertext.md)

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
