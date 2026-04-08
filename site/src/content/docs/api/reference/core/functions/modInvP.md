---
title: "modInvP"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [core](../) / modInvP

# Function: modInvP()

> **modInvP**(`value`, `p`): `bigint`

Computes the multiplicative inverse of a value modulo `p`.

## Parameters

### value

`bigint`

### p

`bigint`

## Returns

`bigint`

## Throws

[InvalidScalarError](../classes/InvalidScalarError/) When `p` is not positive or the inverse
does not exist.
