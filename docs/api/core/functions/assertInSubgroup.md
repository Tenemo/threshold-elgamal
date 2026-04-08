[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [core](../index.md) / assertInSubgroup

# Function: assertInSubgroup()

> **assertInSubgroup**(`value`, `p`, `q`): `void`

Validates that a value is a non-identity element of the prime-order subgroup.

## Parameters

### value

`bigint`

### p

`bigint`

### q

`bigint`

## Returns

`void`

## Throws

[InvalidGroupElementError](../classes/InvalidGroupElementError.md) When the value is outside the
subgroup.
