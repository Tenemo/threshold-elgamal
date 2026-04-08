---
title: "modPowP"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [core](../) / modPowP

# Function: modPowP()

> **modPowP**(`base`, `exponent`, `p`): `bigint`

Computes `base^exponent mod p` for non-negative exponents.

## Parameters

### base

`bigint`

### exponent

`bigint`

### p

`bigint`

## Returns

`bigint`

## Throws

[InvalidScalarError](../classes/InvalidScalarError/) When `p` is not positive or `exponent` is
negative.
