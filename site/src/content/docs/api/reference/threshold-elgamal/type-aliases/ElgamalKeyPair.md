---
title: "ElgamalKeyPair"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold-elgamal](../) / ElgamalKeyPair

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
