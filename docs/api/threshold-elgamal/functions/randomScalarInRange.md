[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / randomScalarInRange

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

[`RandomBytesSource`](../type-aliases/RandomBytesSource.md) = `secureRandomBytesSource`

Optional injected random source used for deterministic tests or custom runtimes.

## Returns

`bigint`

A uniformly sampled bigint in the requested half-open range.

## Throws

[InvalidScalarError](../classes/InvalidScalarError.md) When the range is empty or inverted.
