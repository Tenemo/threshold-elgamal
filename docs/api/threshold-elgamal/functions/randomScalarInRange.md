[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / randomScalarInRange

# Function: randomScalarInRange()

> **randomScalarInRange**(`minInclusive`, `maxExclusive`, `randomSource?`): `bigint`

Samples a uniform scalar from the range `minInclusive..maxExclusive-1`.

## Parameters

### minInclusive

`bigint`

### maxExclusive

`bigint`

### randomSource?

[`RandomBytesSource`](../type-aliases/RandomBytesSource.md) = `secureRandomBytesSource`

## Returns

`bigint`

## Throws

[InvalidScalarError](../classes/InvalidScalarError.md) When the range is empty or inverted.
