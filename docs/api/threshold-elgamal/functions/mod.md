[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / mod

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

[InvalidScalarError](../classes/InvalidScalarError.md) When `modulus` is not positive.
