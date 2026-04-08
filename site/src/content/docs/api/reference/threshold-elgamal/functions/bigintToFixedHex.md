---
title: "bigintToFixedHex"
editUrl: false
---
[**threshold-elgamal**](../../)

***

[threshold-elgamal](../../modules/) / [threshold-elgamal](../) / bigintToFixedHex

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

[InvalidPayloadError](../../core/classes/InvalidPayloadError/) When `byteLength` is not positive.

## Throws

[InvalidScalarError](../../core/classes/InvalidScalarError/) When the value is negative or does not fit
in the requested width.
