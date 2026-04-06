[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / assertInSubgroupOrIdentity

# Function: assertInSubgroupOrIdentity()

> **assertInSubgroupOrIdentity**(`value`, `p`, `q`): `void`

Validates that a value is either the subgroup identity or a non-identity
subgroup element.

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
subgroup-or-identity domain.
