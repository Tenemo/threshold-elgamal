[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / ElgamalKeyPair

# Type alias: ElgamalKeyPair

> **ElgamalKeyPair** = `object`

Public and private key pair for a selected ElGamal suite.

## Properties

### privateKey

> `readonly` **privateKey**: `bigint`

Private scalar `x` in the range `1..q-1`.

***

### publicKey

> `readonly` **publicKey**: `bigint`

Public key `y = g^x mod p`.
