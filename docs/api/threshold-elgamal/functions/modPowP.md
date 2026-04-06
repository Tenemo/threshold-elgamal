[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / modPowP

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

[InvalidScalarError](../classes/InvalidScalarError.md) When `p` is not positive or `exponent` is
negative.
