[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [core](../index.md) / randomScalarBelow

# Function: randomScalarBelow()

> **randomScalarBelow**(`maxExclusive`, `randomSource?`): `bigint`

Samples a uniform scalar from the range `0..maxExclusive-1` with rejection
sampling.

## Parameters

### maxExclusive

`bigint`

Exclusive upper bound for the sampled scalar.

### randomSource?

[`RandomBytesSource`](../type-aliases/RandomBytesSource.md) = `secureRandomBytesSource`

Optional injected random source used for deterministic tests or custom runtimes.

## Returns

`bigint`

A uniformly sampled bigint below `maxExclusive`.

## Throws

[InvalidScalarError](../classes/InvalidScalarError.md) When `maxExclusive` is not positive.
