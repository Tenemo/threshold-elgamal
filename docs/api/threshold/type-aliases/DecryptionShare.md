[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold](../index.md) / DecryptionShare

# Type alias: DecryptionShare

> **DecryptionShare** = `object`

A participant's partial decryption contribution.

## Properties

### index

> `readonly` **index**: `number`

1-based participant index matching the source share.

***

### value

> `readonly` **value**: `bigint`

Partial decryption value `d_i = c1^{x_i} mod p`.
