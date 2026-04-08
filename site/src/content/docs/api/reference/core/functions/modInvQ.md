---
title: "modInvQ"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [core](../) / modInvQ

# Function: modInvQ()

> **modInvQ**(`value`, `q`): `bigint`

Computes the multiplicative inverse of a value modulo `q`.

## Parameters

### value

`bigint`

### q

`bigint`

## Returns

`bigint`

## Throws

[InvalidScalarError](../classes/InvalidScalarError/) When `q` is not positive or the inverse
does not exist.
