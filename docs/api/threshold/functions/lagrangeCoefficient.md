[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold](../index.md) / lagrangeCoefficient

# Function: lagrangeCoefficient()

> **lagrangeCoefficient**(`participantIndex`, `allIndices`, `q`): `bigint`

Computes the Lagrange coefficient for `participantIndex` at `x = 0`.

## Parameters

### participantIndex

`bigint`

Target share index as a bigint.

### allIndices

readonly `bigint`[]

Full subset of indices participating in reconstruction.

### q

`bigint`

Prime-order subgroup order.

## Returns

`bigint`

`lambda_i mod q`.
