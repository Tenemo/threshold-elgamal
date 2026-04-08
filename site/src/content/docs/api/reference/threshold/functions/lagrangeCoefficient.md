---
title: "lagrangeCoefficient"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold](../) / lagrangeCoefficient

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
