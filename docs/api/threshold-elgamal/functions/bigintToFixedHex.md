[**threshold-elgamal**](../../index.md)

***

[threshold-elgamal](../../modules.md) / [threshold-elgamal](../index.md) / bigintToFixedHex

# Function: bigintToFixedHex()

> **bigintToFixedHex**(`value`, `byteLength`): `string`

Encodes a non-negative bigint as fixed-width lowercase hexadecimal.

## Parameters

### value

`bigint`

Non-negative bigint to encode.

### byteLength

`number`

Required output width in bytes.

## Returns

`string`

A lowercase hexadecimal string padded to exactly `byteLength * 2` characters.

## Throws

[InvalidPayloadError](../classes/InvalidPayloadError.md) When `byteLength` is not positive.

## Throws

[InvalidScalarError](../classes/InvalidScalarError.md) When the value is negative or does not fit
in the requested width.
