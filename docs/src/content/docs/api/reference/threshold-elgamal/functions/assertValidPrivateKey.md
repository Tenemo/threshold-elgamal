---
title: "assertValidPrivateKey"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold-elgamal](../) / assertValidPrivateKey

# Function: assertValidPrivateKey()

> **assertValidPrivateKey**(`privateKey`, `group`): `void`

Validates that a private key lies in the range `1..q-1`.

## Parameters

### privateKey

`bigint`

### group

[`CryptoGroup`](../../core/type-aliases/CryptoGroup/)

## Returns

`void`

## Throws

[InvalidScalarError](../../core/classes/InvalidScalarError/) When the private key is zero, negative, or
not strictly less than `q`.
