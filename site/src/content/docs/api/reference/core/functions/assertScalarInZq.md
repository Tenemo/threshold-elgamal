---
title: "assertScalarInZq"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [core](../) / assertScalarInZq

# Function: assertScalarInZq()

> **assertScalarInZq**(`value`, `q`): `void`

Validates that a scalar belongs to `Z_q`.

## Parameters

### value

`bigint`

### q

`bigint`

## Returns

`void`

## Throws

[InvalidScalarError](../classes/InvalidScalarError/) When the value is outside `0..q-1`.
