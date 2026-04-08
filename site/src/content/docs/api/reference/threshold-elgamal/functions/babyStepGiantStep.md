---
title: "babyStepGiantStep"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold-elgamal](../) / babyStepGiantStep

# Function: babyStepGiantStep()

> **babyStepGiantStep**(`target`, `base`, `p`, `bound`): `bigint` \| `null`

Solves a bounded discrete logarithm with the baby-step giant-step method.

It returns `null` instead of throwing when the target does not decode to a
discrete log within the supplied bound.

Runtime and memory both grow roughly with `sqrt(bound)` because the solver
materializes a baby-step table for the searched range.

## Parameters

### target

`bigint`

Group element whose discrete log should be recovered.

### base

`bigint`

Generator used to encode plaintexts.

### p

`bigint`

Prime modulus for the multiplicative group.

### bound

`bigint`

Maximum discrete log to search for.

## Returns

`bigint` \| `null`

The recovered discrete log, or `null` when no solution exists within `bound`.

## Throws

[InvalidScalarError](../../core/classes/InvalidScalarError/) When `bound` is negative.
