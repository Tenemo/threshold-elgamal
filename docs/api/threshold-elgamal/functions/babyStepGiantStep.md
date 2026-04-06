[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / babyStepGiantStep

# Function: babyStepGiantStep()

> **babyStepGiantStep**(`target`, `base`, `p`, `bound`): `bigint` \| `null`

Solves a bounded discrete logarithm with the baby-step giant-step method.

It returns `null` instead of throwing when the target does not decode to a
discrete log within the supplied bound.

## Parameters

### target

`bigint`

### base

`bigint`

### p

`bigint`

### bound

`bigint`

## Returns

`bigint` \| `null`

## Throws

[InvalidScalarError](../classes/InvalidScalarError.md) When `bound` is negative.
