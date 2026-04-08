---
title: "randomScalarInRange"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [core](../) / randomScalarInRange

# Function: randomScalarInRange()

> **randomScalarInRange**(`minInclusive`, `maxExclusive`, `randomSource?`): `bigint`

Samples a uniform scalar from the range `minInclusive..maxExclusive-1`.

## Parameters

### minInclusive

`bigint`

Inclusive lower bound for the sampled scalar.

### maxExclusive

`bigint`

Exclusive upper bound for the sampled scalar.

### randomSource?

[`RandomBytesSource`](../type-aliases/RandomBytesSource/) = `secureRandomBytesSource`

Optional injected random source used for deterministic tests or custom runtimes.

## Returns

`bigint`

A uniformly sampled bigint in the requested half-open range.

## Throws

[InvalidScalarError](../classes/InvalidScalarError/) When the range is empty or inverted.
