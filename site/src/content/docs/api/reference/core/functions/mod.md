---
title: "mod"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [core](../) / mod

# Function: mod()

> **mod**(`value`, `modulus`): `bigint`

Reduces a value into the canonical range `0..modulus-1`.

## Parameters

### value

`bigint`

### modulus

`bigint`

## Returns

`bigint`

## Throws

[InvalidScalarError](../classes/InvalidScalarError/) When `modulus` is not positive.
