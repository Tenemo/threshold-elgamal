[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / assertScalarInZq

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

[InvalidScalarError](../classes/InvalidScalarError.md) When the value is outside `0..q-1`.
