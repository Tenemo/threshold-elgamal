[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / ElgamalCiphertext

# Type alias: ElgamalCiphertext

> **ElgamalCiphertext** = `object`

Standard ElGamal ciphertext pair `(c1, c2)`.

## Properties

### c1

> `readonly` **c1**: `bigint`

Ephemeral component `g^r mod p`.

***

### c2

> `readonly` **c2**: `bigint`

Payload component whose interpretation depends on the selected mode.
