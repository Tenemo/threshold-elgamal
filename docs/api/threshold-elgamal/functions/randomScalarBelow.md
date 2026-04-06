[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / randomScalarBelow

# Function: randomScalarBelow()

> **randomScalarBelow**(`maxExclusive`, `randomSource?`): `bigint`

Samples a uniform scalar from the range `0..maxExclusive-1` with rejection
sampling.

## Parameters

### maxExclusive

`bigint`

### randomSource?

[`RandomBytesSource`](../type-aliases/RandomBytesSource.md) = `secureRandomBytesSource`

## Returns

`bigint`

## Throws

[InvalidScalarError](../classes/InvalidScalarError.md) When `maxExclusive` is not positive.
