---
title: "CryptoGroup"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [core](../) / CryptoGroup

# Type alias: CryptoGroup

> **CryptoGroup** = `object`

Immutable built-in group definition exposed by `getGroup()` and keygen APIs.

## Properties

### bits

> `readonly` **bits**: [`PrimeBits`](PrimeBits/)

Prime modulus size in bits.

***

### byteLength

> `readonly` **byteLength**: `number`

Modulus size in bytes, used by fixed-width encodings.

***

### g

> `readonly` **g**: `bigint`

Primary subgroup generator used for ElGamal keys.

***

### h

> `readonly` **h**: `bigint`

Deterministically derived secondary subgroup generator.

***

### name

> `readonly` **name**: [`GroupName`](GroupName/)

Canonical RFC 7919 suite name.

***

### p

> `readonly` **p**: `bigint`

Safe-prime modulus.

***

### q

> `readonly` **q**: `bigint`

Prime-order subgroup order.

***

### securityEstimate

> `readonly` **securityEstimate**: `number`

Rough classical security estimate in bits.
